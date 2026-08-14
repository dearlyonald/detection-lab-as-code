"""
sigma_eval — a self-contained evaluator for Sigma detection logic.

Why this exists
---------------
Sigma rules are normally *converted* to a backend query language and then run
against a real SIEM. That means the only way to know whether a rule works is to
stand up the whole stack, replay an attack, and look. In CI, that is not an
option.

This module evaluates a Sigma rule directly against a single event dictionary,
in-process, with no SIEM involved. That makes it possible to assert, on every
commit, that:

  * each rule fires on the event it was written for   (true positive)
  * each rule stays silent on benign look-alike events (false positive)

Which is the difference between a rule that has been *written* and a rule that
has been *tested*.

Supported subset
----------------
Deliberately documented rather than implied, because a silent gap in an
evaluator produces green tests for rules that do not work:

  conditions   and / or / not, parentheses, "all of x_*", "1 of x_*",
               "any of x_*", "all of them", "1 of them"
  search ids   maps, lists of maps (OR), lists of keywords (OR substring)
  modifiers    contains, startswith, endswith, re, all, cased, base64,
               base64offset, utf16le/wide, windash, lt, lte, gt, gte, exists
  values       scalars, lists (OR by default, AND with |all), null,
               '*' and '?' wildcards

  NOT supported (raises, never silently ignored):
               near/temporal correlation, field references, aggregations.
               Rules needing those are marked `correlation: true` and are
               excluded from evaluation with an explicit skip, not a pass.

Author: Wael Qumayi
"""

from __future__ import annotations

import base64
import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Union

__all__ = ["SigmaRule", "SigmaEvaluationError", "UnsupportedFeature", "evaluate"]


class SigmaEvaluationError(Exception):
    """Raised when a rule cannot be evaluated at all."""


class UnsupportedFeature(SigmaEvaluationError):
    """Raised for Sigma features this evaluator deliberately does not implement."""


# ---------------------------------------------------------------------------
# Value matching
# ---------------------------------------------------------------------------

_WINDASH_VARIANTS = ["-", "/", "\u2013", "\u2014", "\u2015"]


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _wildcard_match(text: str, pattern: str, cased: bool) -> bool:
    """
    Sigma plain values support '*' and '?'. fnmatch implements exactly those,
    but it also treats '[...]' as a character class, which Sigma does not.
    Escaping brackets keeps Windows paths like 'C:\\Program Files [x86]' literal.
    """
    pattern = pattern.replace("[", "[[]")
    if not cased:
        text, pattern = text.lower(), pattern.lower()
    return fnmatch.fnmatchcase(text, pattern)


def _base64_offset_variants(raw: bytes) -> List[str]:
    """
    A string embedded at an arbitrary offset inside a base64 blob encodes to one
    of three different byte sequences depending on its alignment. Attackers rely
    on this; `|base64offset|contains` exists to defeat it. Reproducing all three
    is what makes the PowerShell encoding rules actually catch real samples.
    """
    out = []
    for pad in range(3):
        encoded = base64.b64encode(b"\x00" * pad + raw).decode("ascii")
        # Strip the bytes contributed by our own padding, and the trailing
        # partial group, leaving only the stable middle section.
        start = (pad * 8 + 5) // 6 if pad else 0
        end = len(encoded) - ((len(raw) + pad) % 3 and 4 or 0)
        chunk = encoded[start:end if end > start else len(encoded)].rstrip("=")
        if chunk:
            out.append(chunk)
    return out


def _compare_scalar(event_value: Any, expected: Any, modifiers: Sequence[str]) -> bool:
    """Apply one expected value against one event value, honouring modifiers."""
    cased = "cased" in modifiers

    # --- null / existence -------------------------------------------------
    if expected is None:
        return event_value is None or event_value == ""
    if "exists" in modifiers:
        want = expected if isinstance(expected, bool) else _as_text(expected).lower() == "true"
        return (event_value is not None) == want

    # --- numeric comparison ----------------------------------------------
    for mod, op in (("lt", "<"), ("lte", "<="), ("gt", ">"), ("gte", ">=")):
        if mod in modifiers:
            try:
                left, right = float(event_value), float(expected)
            except (TypeError, ValueError):
                return False
            return {
                "<": left < right, "<=": left <= right,
                ">": left > right, ">=": left >= right,
            }[op]

    text = _as_text(event_value)
    exp = _as_text(expected)

    # --- regex ------------------------------------------------------------
    if "re" in modifiers:
        flags = 0 if cased else re.IGNORECASE
        try:
            return re.search(exp, text, flags) is not None
        except re.error as err:
            raise SigmaEvaluationError(f"invalid regex {exp!r}: {err}") from err

    # --- encoding transforms ---------------------------------------------
    # PowerShell's -EncodedCommand takes UTF-16LE base64, so a rule hunting for
    # a string inside an encoded command line must encode the needle the same
    # way. Getting this wrong is the most common reason an encoding rule looks
    # correct and never fires.
    wide = "utf16le" in modifiers or "wide" in modifiers
    raw_bytes = exp.encode("utf-16-le") if wide else exp.encode("utf-8")

    candidates = [exp]
    if "base64" in modifiers:
        candidates = [base64.b64encode(raw_bytes).decode("ascii")]
    elif "base64offset" in modifiers:
        candidates = _base64_offset_variants(raw_bytes)
    elif wide:
        raise UnsupportedFeature(
            "the `utf16le`/`wide` modifier is only meaningful together with "
            "`base64` or `base64offset`"
        )
    if "windash" in modifiers and candidates and candidates[0][:1] in _WINDASH_VARIANTS:
        stem = candidates[0][1:]
        candidates = [d + stem for d in _WINDASH_VARIANTS]

    # --- string relations -------------------------------------------------
    hay = text if cased else text.lower()

    def norm(c: str) -> str:
        return c if cased else c.lower()

    if "contains" in modifiers:
        return any(norm(c) in hay for c in candidates)
    if "startswith" in modifiers:
        return any(hay.startswith(norm(c)) for c in candidates)
    if "endswith" in modifiers:
        return any(hay.endswith(norm(c)) for c in candidates)

    # Plain equality, with wildcard support.
    return any(_wildcard_match(text, c, cased) for c in candidates)


def _lookup_field(event: Dict[str, Any], name: str) -> Any:
    """
    Field lookup with a case-insensitive fallback.

    Real Windows telemetry is inconsistent about casing across producers
    (`CommandLine` from Sysmon vs `commandLine` from some shippers). Being
    strict here produces rules that pass in CI and fail in production, which is
    the worst possible outcome, so the fallback is intentional.
    """
    if name in event:
        return event[name]
    lowered = name.lower()
    for key, value in event.items():
        if key.lower() == lowered:
            return value
    return None


def _match_field(event: Dict[str, Any], key: str, expected: Any) -> bool:
    """Evaluate one `Field|mod|mod: value` entry."""
    parts = key.split("|")
    field_name, modifiers = parts[0], [p.lower() for p in parts[1:]]

    unknown = set(modifiers) - {
        "contains", "startswith", "endswith", "re", "all", "cased",
        "base64", "base64offset", "utf16le", "wide", "windash",
        "lt", "lte", "gt", "gte", "exists",
    }
    if unknown:
        raise UnsupportedFeature(f"unsupported modifier(s) {sorted(unknown)} on field {field_name!r}")

    event_value = _lookup_field(event, field_name)

    # A list of expected values is OR by default, AND with the |all modifier.
    if isinstance(expected, list):
        combine = all if "all" in modifiers else any
        return combine(_compare_scalar(event_value, item, modifiers) for item in expected)

    # A multi-valued *event* field matches if any of its values matches.
    if isinstance(event_value, list):
        return any(_compare_scalar(item, expected, modifiers) for item in event_value)

    return _compare_scalar(event_value, expected, modifiers)


def _match_map(event: Dict[str, Any], mapping: Dict[str, Any]) -> bool:
    """All keys within one map must match — Sigma's implicit AND."""
    return all(_match_field(event, k, v) for k, v in mapping.items())


def _match_keywords(event: Dict[str, Any], keywords: Sequence[Any]) -> bool:
    """Keyword search: substring match against any value anywhere in the event."""
    blob = " ".join(_as_text(v) for v in _flatten_values(event)).lower()
    return any(_as_text(k).lower() in blob for k in keywords)


def _flatten_values(obj: Any) -> List[Any]:
    if isinstance(obj, dict):
        return [v for value in obj.values() for v in _flatten_values(value)]
    if isinstance(obj, (list, tuple)):
        return [v for item in obj for v in _flatten_values(item)]
    return [obj]


def _match_search_id(event: Dict[str, Any], definition: Any) -> bool:
    """Evaluate one named search identifier from the `detection` block."""
    if isinstance(definition, dict):
        return _match_map(event, definition)
    if isinstance(definition, list):
        if not definition:
            return False
        if all(isinstance(item, dict) for item in definition):
            return any(_match_map(event, item) for item in definition)  # list of maps = OR
        return _match_keywords(event, definition)
    raise SigmaEvaluationError(f"unsupported search identifier type: {type(definition).__name__}")


# ---------------------------------------------------------------------------
# Condition parsing
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"\(|\)|\||[A-Za-z0-9_*\-\.]+")


@dataclass
class _Parser:
    """Recursive-descent parser for the Sigma condition grammar."""

    tokens: List[str]
    search_ids: List[str]
    pos: int = 0

    def peek(self) -> Union[str, None]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> str:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def parse(self):
        node = self.parse_or()
        if self.pos != len(self.tokens):
            raise SigmaEvaluationError(f"trailing tokens in condition: {self.tokens[self.pos:]}")
        return node

    def parse_or(self):
        node = self.parse_and()
        while (self.peek() or "").lower() == "or":
            self.next()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_not()
        while (self.peek() or "").lower() == "and":
            self.next()
            node = ("and", node, self.parse_not())
        return node

    def parse_not(self):
        if (self.peek() or "").lower() == "not":
            self.next()
            return ("not", self.parse_not())
        return self.parse_primary()

    def parse_primary(self):
        token = self.peek()
        if token is None:
            raise SigmaEvaluationError("unexpected end of condition")

        if token == "(":
            self.next()
            node = self.parse_or()
            if self.peek() != ")":
                raise SigmaEvaluationError("unbalanced parentheses in condition")
            self.next()
            return node

        lowered = token.lower()
        if lowered in ("all", "any", "1") and (
            self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1].lower() == "of"
        ):
            quantifier = self.next().lower()
            self.next()  # consume "of"
            pattern = self.next()
            targets = (
                list(self.search_ids)
                if pattern.lower() == "them"
                else [s for s in self.search_ids if fnmatch.fnmatchcase(s, pattern)]
            )
            if not targets:
                raise SigmaEvaluationError(f"'{quantifier} of {pattern}' matched no search identifiers")
            return ("all_of" if quantifier == "all" else "any_of", targets)

        return ("id", self.next())


def _eval_node(node, event: Dict[str, Any], detection: Dict[str, Any]) -> bool:
    kind = node[0]
    if kind == "id":
        name = node[1]
        if name not in detection:
            raise SigmaEvaluationError(f"condition references unknown search identifier {name!r}")
        return _match_search_id(event, detection[name])
    if kind == "and":
        return _eval_node(node[1], event, detection) and _eval_node(node[2], event, detection)
    if kind == "or":
        return _eval_node(node[1], event, detection) or _eval_node(node[2], event, detection)
    if kind == "not":
        return not _eval_node(node[1], event, detection)
    if kind == "all_of":
        return all(_match_search_id(event, detection[n]) for n in node[1])
    if kind == "any_of":
        return any(_match_search_id(event, detection[n]) for n in node[1])
    raise SigmaEvaluationError(f"unknown node kind {kind!r}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass
class SigmaRule:
    """A parsed Sigma rule, ready to evaluate against events."""

    raw: Dict[str, Any]
    path: str = ""
    _ast: Any = field(default=None, repr=False)
    _detection: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any], path: str = "") -> "SigmaRule":
        detection = data.get("detection")
        if not isinstance(detection, dict):
            raise SigmaEvaluationError(f"{path}: rule has no `detection` block")

        condition = detection.get("condition")
        if condition is None:
            raise SigmaEvaluationError(f"{path}: `detection` has no `condition`")
        if isinstance(condition, list):
            # A list of conditions is an implicit OR.
            condition = " or ".join(f"({c})" for c in condition)

        lowered = condition.lower()
        for unsupported in (" near ", "| count", "|count", "| min", "| max", "|near"):
            if unsupported in lowered:
                raise UnsupportedFeature(
                    f"{path}: condition uses aggregation/correlation ({unsupported.strip()}), "
                    "which this evaluator does not implement. Mark the rule with "
                    "`correlation: true` so CI skips it explicitly instead of passing it silently."
                )

        search_ids = [k for k in detection if k != "condition"]
        tokens = _TOKEN_RE.findall(condition)
        ast = _Parser(tokens=tokens, search_ids=search_ids).parse()
        return cls(raw=data, path=path, _ast=ast, _detection=detection)

    @property
    def id(self) -> str:
        return str(self.raw.get("id", ""))

    @property
    def title(self) -> str:
        return str(self.raw.get("title", ""))

    def matches(self, event: Dict[str, Any]) -> bool:
        """True when this rule fires on `event`."""
        return _eval_node(self._ast, event, self._detection)


def evaluate(rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
    """Convenience one-shot: does `rule` fire on `event`?"""
    return SigmaRule.from_dict(rule).matches(event)
