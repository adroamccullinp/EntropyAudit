"""Report rendering for entropyaudit.

Output is line oriented so results diff cleanly in git, and it is deterministic:
the same input tree always yields byte identical output. Findings are sorted by
path, line, column, then rule id before rendering.
"""

from __future__ import annotations

from collections import Counter

from . import patterns, rationale
from .pyscan import Finding


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: f.sort_key())


def render_scan(findings: list[Finding]) -> list[str]:
