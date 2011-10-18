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
    """Render the scan view: one block per finding with its rationale.

    Returns a list of lines without trailing newlines.
    """
    lines: list[str] = []
    for finding in _sorted_findings(findings):
        rule = patterns.get_rule(finding.rule_id)
        lines.append(
            f"{finding.path}:{finding.line}:{finding.col}: "
            f"{rule.severity.upper()} {finding.rule_id} {rule.title}"
