#!/usr/bin/env python3
"""
sigma_to_wazuh — translate the tested Sigma rules into native Wazuh rules.

Wazuh has no first-class Sigma backend, so a folder of Sigma YAML does nothing
on its own. This converter is what actually makes the detections fire in the
SIEM. It is run by provision/linux/siem/deploy-detections.sh.

Design decisions worth stating
------------------------------
* Sigma's boolean condition is expanded to disjunctive normal form, and each
  resulting clause becomes one Wazuh rule. Wazuh evaluates the <field> elements
  inside a rule as AND, and sibling rules as OR, which is exactly the shape DNF
  produces.

* Negated search identifiers become `negate="yes"` fields.

* What cannot be translated is REPORTED, never silently dropped. A converter
  that quietly skips a rule produces a SIEM that looks configured and is not.
  Unconvertible rules are listed on stderr and the exit code is non-zero.

Supported: field maps, lists of maps, contains/startswith/endswith/re modifiers,
           value lists, and/or/not, "1 of x_*", "all of x_*".
Not supported: keyword searches, base64/base64offset transforms, aggregations.
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML is required:  pip install pyyaml\n")
    sys.exit(2)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sigma_eval import SigmaRule, SigmaEvaluationError  # noqa: E402

# Sigma level -> Wazuh alert level.
LEVEL_MAP = {"informational": 3, "low": 5, "medium": 7, "high": 10, "critical": 13}

# Wazuh's Windows decoder flattens events into these namespaces. Anything not
# listed falls back to win.eventdata.<lowerCamel>, which is where Wazuh puts
# unrecognised EventData fields.
SYSTEM_FIELDS = {
    "EventID": "win.system.eventID",
    "Channel": "win.system.channel",
    "Computer": "win.system.computer",
    "Provider_Name": "win.system.providerName",
    "Level": "win.system.level",
}

# Linux auditd namespace, as produced by the Wazuh audit decoder.
LINUX_FIELDS = {
    "CommandLine": "audit.command",
    "Image": "audit.exe",
    "User": "audit.uid",
    "ParentImage": "audit.ppid",
    "Computer": "agent.name",
}

# Base rule to chain from, by log source. 60009 is the Wazuh sibling for
# Windows eventchannel events; 92000-range for Sysmon.
IF_SID = {
    "security": "60009",
    "sysmon": "61600",
    "powershell": "60009",
    "system": "60009",
    "linux": "5000",
}


class Unconvertible(Exception):
    """Raised when a rule uses a Sigma feature Wazuh cannot express."""


# ---------------------------------------------------------------------------
# Condition -> disjunctive normal form
# ---------------------------------------------------------------------------

Clause = Tuple[Set[str], Set[str]]  # (positive search ids, negated search ids)


def to_dnf(node) -> List[Clause]:
    kind = node[0]

    if kind == "id":
        return [({node[1]}, set())]

    if kind == "all_of":
        return [(set(node[1]), set())]

    if kind == "any_of":
        return [({name}, set()) for name in node[1]]

    if kind == "and":
        left, right = to_dnf(node[1]), to_dnf(node[2])
        return [(lp | rp, ln | rn) for lp, ln in left for rp, rn in right]

    if kind == "or":
        return to_dnf(node[1]) + to_dnf(node[2])

    if kind == "not":
        inner = node[1]
        # De Morgan over the shapes that actually occur in Sigma conditions.
        if inner[0] == "id":
            return [(set(), {inner[1]})]
        if inner[0] == "any_of":          # not (a or b)  ->  not a and not b
            return [(set(), set(inner[1]))]
        if inner[0] == "all_of":          # not (a and b) ->  not a or not b
            return [(set(), {name}) for name in inner[1]]
        raise Unconvertible("negation of a compound expression is not supported")

    raise Unconvertible(f"unsupported condition node {kind!r}")


# ---------------------------------------------------------------------------
# Field translation
# ---------------------------------------------------------------------------


def wazuh_field(name: str, product: str) -> str:
    if product == "linux":
        # The auditd decoder uses a completely different namespace from the
        # Windows one. Emitting win.eventdata.* for a Linux rule produces XML
        # that loads cleanly and can never match anything.
        return LINUX_FIELDS.get(name, f"audit.{name[0].lower()}{name[1:]}")
    if name in SYSTEM_FIELDS:
        return SYSTEM_FIELDS[name]
    return f"win.eventdata.{name[0].lower()}{name[1:]}"


def to_regex(value: Any, modifiers: List[str]) -> str:
    """Turn one Sigma value plus its modifiers into a Wazuh (PCRE2) pattern."""
    if value is None:
        return "^$"

    text = str(value)

    if "re" in modifiers:
        return text

    unsupported = {"base64", "base64offset", "utf16le", "wide", "windash"} & set(modifiers)
    if unsupported:
        raise Unconvertible(f"modifier(s) {sorted(unsupported)} cannot be expressed as a Wazuh pattern")

    # Sigma wildcards become regex; everything else is escaped literally.
    escaped = re.escape(text).replace(r"\*", ".*").replace(r"\?", ".")

    if "contains" in modifiers:
        return escaped
    if "startswith" in modifiers:
        return "^" + escaped
    if "endswith" in modifiers:
        return escaped + "$"
    return "^" + escaped + "$"


def field_elements(mapping: Dict[str, Any], negate: bool, product: str) -> List[str]:
    """Render one search-identifier map as Wazuh <field> elements."""
    out = []
    for key, value in mapping.items():
        parts = key.split("|")
        name, modifiers = parts[0], [p.lower() for p in parts[1:]]

        if isinstance(value, list):
            if "all" in modifiers:
                # AND across values: Wazuh has no single-field AND, so emit one
                # <field> element per value. Wazuh ANDs sibling fields, and
                # repeating the same field name is permitted.
                patterns = [to_regex(v, modifiers) for v in value]
            else:
                patterns = ["|".join(f"(?:{to_regex(v, modifiers)})" for v in value)]
        else:
            patterns = [to_regex(value, modifiers)]

        attr = ' negate="yes"' if negate else ""
        for pattern in patterns:
            out.append(
                f'    <field name="{wazuh_field(name, product)}"{attr}>'
                f"{html.escape(pattern)}</field>"
            )
    return out


def expand_search_id(definition: Any) -> List[Dict[str, Any]]:
    """A search id is either one map, or a list of maps meaning OR."""
    if isinstance(definition, dict):
        return [definition]
    if isinstance(definition, list):
        if all(isinstance(item, dict) for item in definition):
            return definition
        raise Unconvertible("keyword searches cannot be converted to Wazuh fields")
    raise Unconvertible(f"unsupported search identifier of type {type(definition).__name__}")


def pick_if_sid(rule: Dict[str, Any]) -> str:
    logsource = rule.get("logsource") or {}
    service = str(logsource.get("service", "")).lower()
    category = str(logsource.get("category", "")).lower()
    product = str(logsource.get("product", "")).lower()

    if product == "linux":
        return IF_SID["linux"]
    if service in IF_SID:
        return IF_SID[service]
    if category in ("process_creation", "process_access", "registry_set", "image_load"):
        return IF_SID["sysmon"]
    return IF_SID["security"]


# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------


def convert_rule(rule: Dict[str, Any], rule_id: int) -> Tuple[List[str], int]:
    compiled = SigmaRule.from_dict(rule)
    detection = compiled._detection  # noqa: SLF001 — same package, deliberate
    clauses = to_dnf(compiled._ast)  # noqa: SLF001

    level = LEVEL_MAP.get(str(rule.get("level", "medium")).lower(), 7)
    if_sid = pick_if_sid(rule)
    product = str((rule.get("logsource") or {}).get("product", "")).lower()
    title = html.escape(str(rule.get("title", "Untitled")))
    sigma_id = rule.get("id", "")

    techniques = [
        str(t).split(".", 1)[1].upper()
        for t in (rule.get("tags") or [])
        if str(t).lower().startswith("attack.t")
    ]

    xml: List[str] = []
    emitted = 0

    for clause_index, (positives, negatives) in enumerate(clauses):
        # Each positive search id that is a list-of-maps multiplies the clause.
        positive_variants: List[List[Dict[str, Any]]] = [[]]
        for name in sorted(positives):
            maps = expand_search_id(detection[name])
            positive_variants = [prev + [m] for prev in positive_variants for m in maps]

        negative_maps: List[Dict[str, Any]] = []
        for name in sorted(negatives):
            negative_maps.extend(expand_search_id(detection[name]))

        for variant in positive_variants:
            fields: List[str] = []
            for mapping in variant:
                fields.extend(field_elements(mapping, negate=False, product=product))
            for mapping in negative_maps:
                fields.extend(field_elements(mapping, negate=True, product=product))

            if not fields:
                continue

            suffix = "" if len(clauses) == 1 and len(positive_variants) == 1 else f" [{clause_index + 1}]"
            xml.append(f'  <rule id="{rule_id + emitted}" level="{level}">')
            xml.append(f"    <if_sid>{if_sid}</if_sid>")
            xml.extend(fields)
            xml.append(f"    <description>{title}{suffix}</description>")
            for technique in techniques:
                xml.append(f"    <mitre><id>{technique}</id></mitre>")
            xml.append(f"    <info type=\"link\">sigma:{sigma_id}</info>")
            xml.append("  </rule>")
            emitted += 1

    return xml, emitted


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert Sigma rules to Wazuh rules.")
    ap.add_argument("--input", required=True, help="directory containing Sigma .yml rules")
    ap.add_argument("--output", required=True, help="Wazuh rules XML file to write")
    ap.add_argument("--base-id", type=int, default=100100, help="first Wazuh rule id to allocate")
    args = ap.parse_args()

    in_dir = Path(args.input)
    rule_files = sorted(in_dir.rglob("*.yml"))
    if not rule_files:
        sys.stderr.write(f"no rules found under {in_dir}\n")
        return 2

    body: List[str] = []
    next_id = args.base_id
    converted, skipped = 0, []

    for path in rule_files:
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(rule, dict):
                raise Unconvertible("not a YAML mapping")
            if rule.get("correlation"):
                raise Unconvertible("correlation rules must be built as Wazuh composite rules by hand")

            xml, emitted = convert_rule(rule, next_id)
            if not emitted:
                raise Unconvertible("produced no usable field conditions")

            body.append(f"\n  <!-- {path.name} -->")
            body.extend(xml)
            next_id += emitted
            converted += 1

        except (Unconvertible, SigmaEvaluationError, yaml.YAMLError) as err:
            skipped.append((path.name, str(err)))

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "<!--\n"
        "  Generated by tools/sigma_to_wazuh.py — do not edit by hand.\n"
        "  Source of truth is detections/sigma/. Regenerate after any rule change.\n"
        "-->\n"
        '<group name="detection-lab,sigma,">\n'
        + "\n".join(body)
        + "\n</group>\n",
        encoding="utf-8",
    )

    print(f"converted {converted}/{len(rule_files)} rules into {next_id - args.base_id} Wazuh rules -> {out}")

    if skipped:
        # Loud, itemised, and non-zero exit. Silence here would mean shipping a
        # SIEM that is missing detections nobody knows are missing.
        sys.stderr.write(f"\n{len(skipped)} rule(s) could NOT be converted:\n")
        for name, reason in skipped:
            sys.stderr.write(f"  - {name}: {reason}\n")
        sys.stderr.write(
            "\nThese still pass tools/validate_sigma.py and remain valid Sigma; they simply\n"
            "cannot be expressed as native Wazuh rules. Deploy them through a Sigma-aware\n"
            "pipeline, or rewrite the detection to avoid the unsupported construct.\n"
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
