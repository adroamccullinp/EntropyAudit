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
        )
        lines.append(f"    category: {rule.category} ({rule.cwe})")
        lines.append(f"    code: {finding.snippet}")
        lines.append(f"    why: {rationale.explain(finding.rule_id)}")
        lines.append("")
    lines.append(_summary_line(findings))
    return lines


def render_report(findings: list[Finding], root: str) -> list[str]:
    """Render a grouped report suitable for a human reviewer.

    Groups findings by CWE-style category and counts them, then lists each
    finding compactly under its category.
    """
    lines: list[str] = []
    lines.append(f"entropyaudit report for {root}")
    lines.append("=" * len(lines[0]))
    lines.append("")

    counts = category_counts(findings)
    lines.append("findings by class:")
    for category in sorted(counts):
        lines.append(f"    {counts[category]:>3}  {category}")
    lines.append("")

    by_cat: dict[str, list[Finding]] = {}
    for finding in _sorted_findings(findings):
        rule = patterns.get_rule(finding.rule_id)
        by_cat.setdefault(rule.category, []).append(finding)

    for category in sorted(by_cat):
        lines.append(category)
        for finding in by_cat[category]:
            rule = patterns.get_rule(finding.rule_id)
            lines.append(
                f"    {finding.path}:{finding.line}:{finding.col} "
                f"[{rule.severity}] {finding.rule_id} {rule.title}"
            )
        lines.append("")

    lines.append(_summary_line(findings))
    return lines


def category_counts(findings: list[Finding]) -> dict[str, int]:
    """Return a mapping of CWE-style category to finding count."""
    counter: Counter[str] = Counter()
    for finding in findings:
        rule = patterns.get_rule(finding.rule_id)
        counter[rule.category] += 1
    return dict(counter)


def _summary_line(findings: list[Finding]) -> str:
    total = len(findings)
    if total == 0:
        return "0 findings"
    high = sum(
        1 for f in findings if patterns.get_rule(f.rule_id).severity == "high"
    )
    medium = sum(
        1 for f in findings if patterns.get_rule(f.rule_id).severity == "medium"
    )
    low = sum(
        1 for f in findings if patterns.get_rule(f.rule_id).severity == "low"
    )
    noun = "finding" if total == 1 else "findings"
    return f"{total} {noun}: {high} high, {medium} medium, {low} low"
