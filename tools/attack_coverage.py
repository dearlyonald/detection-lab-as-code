#!/usr/bin/env python3
"""
attack_coverage — measure what this repository actually detects.

Two questions this answers, both of which are usually guessed at:

  1. Which ATT&CK techniques do the rules claim to cover?
     Read from the `tags` of every rule. Produces an ATT&CK Navigator layer you
     can drop straight onto https://mitre-attack.github.io/attack-navigator/

  2. Of the techniques actually executed in a scenario run, how many were
     covered by a rule?
     Joins attack/results/<run_id>.json against the rule set and reports the
     gaps by name. The gaps are the point - a coverage report that only lists
     successes is marketing, not measurement.

Usage
    python tools/attack_coverage.py
    python tools/attack_coverage.py --run 01-domain-compromise-20260814-113000
    python tools/attack_coverage.py --navigator out/layer.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML is required:  pip install pyyaml\n")
    sys.exit(2)

REPO = Path(__file__).resolve().parent.parent
RULES_DIR = REPO / "detections" / "sigma"
RESULTS_DIR = REPO / "attack" / "results"
SCENARIOS_DIR = REPO / "attack" / "scenarios"

_TTY = sys.stdout.isatty()
GRN = "\033[0;32m" if _TTY else ""
RED = "\033[0;31m" if _TTY else ""
YEL = "\033[0;33m" if _TTY else ""
CYN = "\033[0;36m" if _TTY else ""
DIM = "\033[2m" if _TTY else ""
RST = "\033[0m" if _TTY else ""

TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

# ATT&CK tactic tags, in kill-chain order rather than alphabetical, so the
# report reads as an intrusion rather than as a glossary.
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def load_rules() -> List[dict]:
    rules = []
    for path in sorted(RULES_DIR.rglob("*.yml")):
        try:
            with path.open(encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if isinstance(data, dict):
                data["_path"] = str(path.relative_to(REPO))
                rules.append(data)
        except yaml.YAMLError as err:
            sys.stderr.write(f"{RED}skipping unparseable rule {path.name}: {err}{RST}\n")
    return rules


def techniques_of(rule: dict) -> Set[str]:
    out = set()
    for tag in rule.get("tags") or []:
        m = TECHNIQUE_RE.match(str(tag).strip())
        if m:
            out.add(m.group(1).upper())
    return out


def tactics_of(rule: dict) -> Set[str]:
    return {
        str(t).split(".", 1)[1].lower()
        for t in (rule.get("tags") or [])
        if str(t).lower().startswith("attack.") and not TECHNIQUE_RE.match(str(t).strip())
    }


# ---------------------------------------------------------------------------
# Report 1 — what the rule set covers
# ---------------------------------------------------------------------------


def report_rule_coverage(rules: List[dict]) -> Dict[str, List[str]]:
    by_technique: Dict[str, List[str]] = defaultdict(list)
    by_tactic: Dict[str, Set[str]] = defaultdict(set)

    for rule in rules:
        title = rule.get("title", rule["_path"])
        for tech in techniques_of(rule):
            by_technique[tech].append(title)
        for tac in tactics_of(rule):
            by_tactic[tac].update(techniques_of(rule))

    print(f"\n{CYN}ATT&CK coverage of the current rule set{RST}")
    print(f"{DIM}{len(rules)} rules covering {len(by_technique)} techniques"
          f" across {len(by_tactic)} tactics{RST}")
    # Sigma tags list tactics and techniques as a flat set, with no pairing
    # between them. A rule tagged with two tactics therefore has its techniques
    # listed under both. Stated rather than silently glossed over.
    print(f"{DIM}note: tactic grouping is per-rule, so a rule tagged with two "
          f"tactics lists its techniques under each{RST}\n")

    for tactic in TACTIC_ORDER:
        if tactic not in by_tactic:
            continue
        techs = sorted(by_tactic[tactic])
        print(f"  {tactic}")
        for tech in techs:
            rule_names = by_technique.get(tech, [])
            print(f"    {GRN}{tech:<12}{RST} {DIM}{len(rule_names)} rule(s){RST}  {rule_names[0][:52]}")
        print()

    # Tactics with no rule at all. Naming these is the most useful line in the
    # whole report, because it is the backlog.
    uncovered = [t for t in TACTIC_ORDER if t not in by_tactic]
    if uncovered:
        print(f"  {YEL}tactics with no coverage yet{RST}")
        print(f"    {DIM}{', '.join(uncovered)}{RST}\n")

    return {k: v for k, v in by_technique.items()}


# ---------------------------------------------------------------------------
# Report 2 — what a scenario run exercised versus what is covered
# ---------------------------------------------------------------------------


def scenario_techniques(scenario_name: str) -> Dict[str, str]:
    """Read technique -> friendly name from a scenario definition."""
    path = SCENARIOS_DIR / f"{scenario_name}.yml"
    if not path.exists():
        return {}
    out, current = {}, None
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\s*-\s+technique:\s*(\S+)", line)
        if m:
            current = m.group(1).upper()
            out[current] = current
            continue
        m = re.match(r'^\s+name:\s*"?([^"]+)"?\s*$', line)
        if m and current:
            out[current] = m.group(1).strip()
    return out


def report_run(run_id: str, by_technique: Dict[str, List[str]]) -> int:
    run_path = RESULTS_DIR / f"{run_id}.json"
    if not run_path.exists():
        available = sorted(p.stem for p in RESULTS_DIR.glob("*.json")) if RESULTS_DIR.exists() else []
        sys.stderr.write(f"{RED}no run record at {run_path}{RST}\n")
        if available:
            sys.stderr.write("available runs:\n  " + "\n  ".join(available) + "\n")
        else:
            sys.stderr.write(
                "Run a scenario on ws01 first:\n"
                "  .\\attack\\run-atomic.ps1 -Scenario 01-domain-compromise\n"
                "then copy attack\\results\\*.json back to the host.\n"
            )
        return 2

    run = json.loads(run_path.read_text(encoding="utf-8"))
    executions = run.get("executions", [])

    print(f"\n{CYN}Scenario run: {run.get('scenario')}{RST}")
    print(f"{DIM}host {run.get('host')}   started {run.get('started_utc')}   "
          f"{len(executions)} techniques{RST}\n")

    detected, missed, failed = [], [], []
    for ex in executions:
        tech = str(ex.get("technique", "")).upper()
        name = ex.get("name", tech)
        if ex.get("status") == "error":
            failed.append((tech, name, ex.get("error", "")))
            continue
        if ex.get("status") != "completed":
            continue
        # A rule covers a sub-technique if it tags the sub-technique itself or
        # its parent (e.g. a rule tagged T1003 covers T1003.001).
        parent = tech.split(".")[0]
        rules = by_technique.get(tech) or by_technique.get(parent) or []
        (detected if rules else missed).append((tech, name, rules))

    if detected:
        print(f"  {GRN}covered{RST}")
        for tech, name, rules in detected:
            print(f"    {GRN}+{RST} {tech:<12} {name[:44]:<44} {DIM}{rules[0][:40]}{RST}")
        print()

    if missed:
        print(f"  {RED}executed but NOT covered by any rule{RST}")
        for tech, name, _ in missed:
            print(f"    {RED}-{RST} {tech:<12} {name[:44]}")
        print(f"    {DIM}each of these is a rule waiting to be written{RST}\n")

    if failed:
        print(f"  {YEL}technique did not execute{RST}")
        for tech, name, err in failed:
            print(f"    {YEL}!{RST} {tech:<12} {name[:38]:<38} {DIM}{str(err)[:40]}{RST}")
        print(f"    {DIM}these are excluded from the ratio - a test that did not run "
              f"proves nothing either way{RST}\n")

    executed = len(detected) + len(missed)
    pct = (len(detected) / executed * 100) if executed else 0.0
    print("-" * 72)
    print(f"  detection coverage : {len(detected)}/{executed} executed techniques  ({pct:.0f}%)")
    print(f"  gaps               : {len(missed)}")
    print(f"  did not execute    : {len(failed)}")
    print("-" * 72 + "\n")
    return 0


# ---------------------------------------------------------------------------
# ATT&CK Navigator layer
# ---------------------------------------------------------------------------


def write_navigator(by_technique: Dict[str, List[str]], out_path: Path) -> None:
    layer = {
        "name": "detection-lab-as-code coverage",
        "versions": {"attack": "15", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques covered by tested Sigma rules in detection-lab-as-code",
        "sorting": 3,
        "hideDisabled": False,
        "techniques": [
            {
                "techniqueID": tech,
                "score": min(len(rules) * 50, 100),
                "comment": "; ".join(rules),
                "enabled": True,
            }
            for tech, rules in sorted(by_technique.items())
        ],
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#0b5fa5"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "1 rule", "color": "#66b1ff"},
            {"label": "2+ rules", "color": "#0b5fa5"},
        ],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    print(f"{GRN}Navigator layer written to {out_path.relative_to(REPO)}{RST}")
    print(f"{DIM}Load it at https://mitre-attack.github.io/attack-navigator/ "
          f"-> Open Existing Layer -> Upload from local{RST}\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure ATT&CK coverage of the rule set.")
    ap.add_argument("--run", help="scenario run id under attack/results/ to score against")
    ap.add_argument("--navigator", nargs="?", const="out/attack-navigator-layer.json",
                    help="write an ATT&CK Navigator layer (default out/attack-navigator-layer.json)")
    args = ap.parse_args()

    rules = load_rules()
    if not rules:
        sys.stderr.write(f"{RED}no rules found under {RULES_DIR}{RST}\n")
        return 2

    by_technique = report_rule_coverage(rules)

    if args.navigator:
        write_navigator(by_technique, REPO / args.navigator)

    if args.run:
        return report_run(args.run, by_technique)

    return 0


if __name__ == "__main__":
    sys.exit(main())
