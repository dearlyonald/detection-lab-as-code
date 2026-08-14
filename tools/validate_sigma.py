#!/usr/bin/env python3
"""
validate_sigma — the quality gate for every detection in this repository.

Run locally:      python tools/validate_sigma.py
Run in CI:        same command; a non-zero exit fails the build.
Verbose:          python tools/validate_sigma.py -v

What it enforces
----------------
1. STRUCTURE   every rule parses, has a valid condition, and every search
               identifier the condition names actually exists.

2. POLICY      the metadata contract from lab.yml `detection_policy`:
               a UUID, an author, an ATT&CK tag, references, a documented
               false-positive list, an allowed level and status.

3. BEHAVIOUR   the part that matters. Every rule ships with sample events and
               must fire on the true positives and stay silent on the false
               positives. A rule with no tests fails — "untested" is not a
               state a detection is allowed to be in.

Exit codes:  0 = all green, 1 = failures, 2 = could not run.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("PyYAML is required:  pip install pyyaml\n")
    sys.exit(2)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sigma_eval import SigmaRule, SigmaEvaluationError, UnsupportedFeature  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
RULES_DIR = REPO / "detections" / "sigma"
TESTS_DIR = REPO / "detections" / "tests"

# ANSI colours, disabled when the output is redirected.
_TTY = sys.stdout.isatty()
RED = "\033[0;31m" if _TTY else ""
GRN = "\033[0;32m" if _TTY else ""
YEL = "\033[0;33m" if _TTY else ""
CYN = "\033[0;36m" if _TTY else ""
DIM = "\033[2m" if _TTY else ""
RST = "\033[0m" if _TTY else ""


@dataclass
class Result:
    rule_path: Path
    title: str = ""
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    tp_pass: int = 0
    tp_total: int = 0
    fp_pass: int = 0
    fp_total: int = 0
    skipped: bool = False

    @property
    def ok(self) -> bool:
        return not self.errors


def load_policy() -> Dict[str, Any]:
    lab = REPO / "lab.yml"
    if not lab.exists():
        return {}
    with lab.open(encoding="utf-8") as fh:
        return (yaml.safe_load(fh) or {}).get("detection_policy", {})


# ---------------------------------------------------------------------------
# 2. Metadata policy
# ---------------------------------------------------------------------------


def check_policy(rule: Dict[str, Any], policy: Dict[str, Any], res: Result) -> None:
    if policy.get("require_uuid", True):
        rid = rule.get("id")
        if not rid:
            res.errors.append("missing `id` — every rule needs a stable UUID so alerts can be traced back to it")
        else:
            try:
                uuid.UUID(str(rid))
            except ValueError:
                res.errors.append(f"`id` is not a valid UUID: {rid!r}")

    if policy.get("require_author", True) and not rule.get("author"):
        res.errors.append("missing `author`")

    if not rule.get("description"):
        res.errors.append("missing `description`")
    elif len(str(rule["description"])) < 40:
        res.warnings.append("`description` is very short — an analyst reading the alert at 3am needs context")

    # ATT&CK mapping. Coverage you cannot measure is coverage you do not have.
    if policy.get("require_attack_tag", True):
        tags = [str(t).lower() for t in (rule.get("tags") or [])]
        technique_tags = [t for t in tags if t.startswith("attack.t")]
        if not technique_tags:
            res.errors.append("no ATT&CK technique tag (expected e.g. `attack.t1059.001`)")

    if policy.get("require_references", True) and not rule.get("references"):
        res.errors.append("missing `references` — a rule with no source is a guess")

    # False positives are mandatory. A rule whose author cannot name a way it
    # could be wrong has not thought about it hard enough.
    if policy.get("require_falsepositives", True):
        fps = rule.get("falsepositives")
        if not fps:
            res.errors.append("missing `falsepositives`")
        elif [str(f).strip().lower() for f in fps] in (["unknown"], ["none"]):
            res.errors.append("`falsepositives` is 'Unknown' — name a real scenario or lower the rule's level")

    level = str(rule.get("level", "")).lower()
    allowed_levels = policy.get("allowed_levels") or []
    if allowed_levels and level not in allowed_levels:
        res.errors.append(f"`level` {level!r} not in {allowed_levels}")

    status = str(rule.get("status", "")).lower()
    allowed_status = policy.get("allowed_status") or []
    if allowed_status and status and status not in allowed_status:
        res.errors.append(f"`status` {status!r} not in {allowed_status}")

    if not rule.get("logsource"):
        res.errors.append("missing `logsource`")


# ---------------------------------------------------------------------------
# 3. Behavioural tests
# ---------------------------------------------------------------------------


def find_test_file(rule_path: Path) -> Path:
    return TESTS_DIR / f"{rule_path.stem}.test.yml"


def run_tests(compiled: SigmaRule, rule_path: Path, policy: Dict[str, Any], res: Result, verbose: bool) -> None:
    test_path = find_test_file(rule_path)
    min_tp = int(policy.get("min_true_positive_tests", 1))
    min_fp = int(policy.get("min_false_positive_tests", 1))

    if not test_path.exists():
        res.errors.append(
            f"no test file at detections/tests/{test_path.name} — "
            "a rule without tests is an untested assumption"
        )
        return

    with test_path.open(encoding="utf-8") as fh:
        spec = yaml.safe_load(fh) or {}

    tps = spec.get("true_positives") or []
    fps = spec.get("false_positives") or []
    res.tp_total, res.fp_total = len(tps), len(fps)

    if len(tps) < min_tp:
        res.errors.append(f"only {len(tps)} true-positive test(s), policy requires {min_tp}")
    if len(fps) < min_fp:
        res.errors.append(
            f"only {len(fps)} false-positive test(s), policy requires {min_fp}. "
            "Proving a rule does NOT fire on benign activity is half its value"
        )

    for case in tps:
        name = case.get("name", "<unnamed>")
        event = case.get("event") or {}
        try:
            fired = compiled.matches(event)
        except SigmaEvaluationError as err:
            res.errors.append(f"TP '{name}': evaluation error: {err}")
            continue
        if fired:
            res.tp_pass += 1
            if verbose:
                print(f"      {GRN}fires{RST}  {DIM}TP{RST} {name}")
        else:
            res.errors.append(f"TP '{name}': rule did NOT fire but should have")

    for case in fps:
        name = case.get("name", "<unnamed>")
        event = case.get("event") or {}
        try:
            fired = compiled.matches(event)
        except SigmaEvaluationError as err:
            res.errors.append(f"FP '{name}': evaluation error: {err}")
            continue
        if not fired:
            res.fp_pass += 1
            if verbose:
                print(f"      {GRN}silent{RST} {DIM}FP{RST} {name}")
        else:
            res.errors.append(
                f"FP '{name}': rule FIRED on benign activity — this is a false positive "
                "that would reach an analyst"
            )


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def validate_rule(path: Path, policy: Dict[str, Any], verbose: bool) -> Result:
    res = Result(rule_path=path)
    try:
        with path.open(encoding="utf-8") as fh:
            rule = yaml.safe_load(fh)
    except yaml.YAMLError as err:
        res.errors.append(f"invalid YAML: {err}")
        return res

    if not isinstance(rule, dict):
        res.errors.append("rule is not a YAML mapping")
        return res

    res.title = str(rule.get("title", path.stem))

    check_policy(rule, policy, res)

    if rule.get("correlation"):
        res.skipped = True
        res.warnings.append("correlation rule — behaviour tests skipped (evaluator does not do aggregation)")
        return res

    try:
        compiled = SigmaRule.from_dict(rule, path=str(path))
    except UnsupportedFeature as err:
        res.errors.append(str(err))
        return res
    except SigmaEvaluationError as err:
        res.errors.append(f"detection logic error: {err}")
        return res

    run_tests(compiled, path, policy, res, verbose)
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate and test the Sigma rules in this repository.")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every individual test case")
    ap.add_argument("--rule", help="validate a single rule by filename stem")
    args = ap.parse_args()

    if not RULES_DIR.exists():
        sys.stderr.write(f"no rules directory at {RULES_DIR}\n")
        return 2

    policy = load_policy()
    rule_files = sorted(RULES_DIR.rglob("*.yml"))
    if args.rule:
        rule_files = [p for p in rule_files if p.stem == args.rule]
        if not rule_files:
            sys.stderr.write(f"no rule with stem {args.rule!r}\n")
            return 2

    if not rule_files:
        sys.stderr.write("no rules found\n")
        return 2

    print(f"\n{CYN}detection-lab-as-code — rule validation{RST}")
    print(f"{DIM}{len(rule_files)} rule(s) in {RULES_DIR.relative_to(REPO)}{RST}\n")

    results = []
    for path in rule_files:
        res = validate_rule(path, policy, args.verbose)
        results.append(res)

        rel = path.relative_to(REPO)
        if res.skipped:
            mark, colour = "SKIP", YEL
        elif res.ok:
            mark, colour = "PASS", GRN
        else:
            mark, colour = "FAIL", RED

        counts = ""
        if res.tp_total or res.fp_total:
            counts = f"{DIM}[TP {res.tp_pass}/{res.tp_total}  FP {res.fp_pass}/{res.fp_total}]{RST}"
        print(f"  {colour}{mark}{RST}  {res.title[:58]:<58} {counts}")
        if args.verbose:
            print(f"        {DIM}{rel}{RST}")
        for w in res.warnings:
            print(f"        {YEL}warn{RST} {w}")
        for e in res.errors:
            print(f"        {RED}fail{RST} {e}")

    failed = [r for r in results if not r.ok]
    skipped = [r for r in results if r.skipped]
    tp_pass = sum(r.tp_pass for r in results)
    tp_total = sum(r.tp_total for r in results)
    fp_pass = sum(r.fp_pass for r in results)
    fp_total = sum(r.fp_total for r in results)

    print(f"\n{'-' * 72}")
    print(f"  rules      : {len(results)}   passed {len(results) - len(failed) - len(skipped)}"
          f"   failed {len(failed)}   skipped {len(skipped)}")
    print(f"  detection  : {tp_pass}/{tp_total} true positives fired")
    print(f"  precision  : {fp_pass}/{fp_total} benign events correctly ignored")
    print(f"{'-' * 72}\n")

    if failed:
        print(f"{RED}FAILED{RST} — {len(failed)} rule(s) need attention\n")
        return 1

    print(f"{GRN}All rules validated.{RST}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
