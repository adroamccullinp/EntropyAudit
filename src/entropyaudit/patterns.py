"""Rule definitions for entropyaudit.

Each rule has a stable identifier, a severity, a CWE-style category, and a short
title. The written exploitability rationale lives in rationale.py so the report
always carries an explanation rather than a bare rule code.

Severity ordering, from most to least serious: high, medium, low.
"""

from __future__ import annotations

from dataclasses import dataclass


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class Rule:
    """A single detection rule."""

    rule_id: str
    title: str
    severity: str
    category: str  # CWE-style category label
    cwe: str


# Rule identifiers are referenced by pyscan.py when it records a finding and by
# rationale.py when it renders the explanation. Keep them stable.
RULES = {
    "EA001": Rule(
        rule_id="EA001",
        title="Predictable seed passed to random generator",
        severity="high",
        category="Use of Insufficiently Random Values",
        cwe="CWE-330",
    ),
    "EA002": Rule(
        rule_id="EA002",
        title="random module used on a security-relevant path",
        severity="high",
        category="Use of Cryptographically Weak PRNG",
        cwe="CWE-338",
    ),
    "EA003": Rule(
        rule_id="EA003",
        title="Generator seeded from wall-clock time",
        severity="high",
        category="Predictable Seed in PRNG",
        cwe="CWE-337",
    ),
    "EA004": Rule(
        rule_id="EA004",
        title="Reused nonce or IV bound to a constant",
        severity="high",
        category="Reusing a Nonce or Key Pair in Encryption",
        cwe="CWE-323",
    ),
    "EA005": Rule(
        rule_id="EA005",
        title="Fixed salt used for key derivation or hashing",
        severity="medium",
        category="Use of a One-Way Hash with a Predictable Salt",
        cwe="CWE-760",
    ),
    "EA006": Rule(
        rule_id="EA006",
        title="Weak hash used for password handling",
        severity="high",
        category="Use of Password Hash With Insufficient Computational Effort",
        cwe="CWE-916",
    ),
}


def get_rule(rule_id: str) -> Rule:
    """Return the rule for rule_id, raising KeyError if unknown."""
    return RULES[rule_id]


def all_rules_sorted() -> list[Rule]:
    """Return every rule sorted by rule_id for deterministic listing."""
    return [RULES[k] for k in sorted(RULES)]
