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
