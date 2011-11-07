"""Command line interface for entropyaudit.

Subcommands:

    scan     walk a path and print each finding with its rationale
    report   walk a path and print a grouped report by finding class
    explain  print the rationale for one rule id, or list all rules
    version  print the package version

Exit codes: 0 clean, 1 findings present, 2 usage error. argparse itself exits
with 2 on argument errors, which matches the standard.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__, patterns, rationale, report
from .pyscan import Finding, scan_file


def _iter_python_files(root: str):
    """Yield Python file paths under root in sorted, deterministic order.

    If root is a single file it is yielded directly.
    """
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


def _normalize_path(path: str) -> str:
    """Return a forward-slash relative-ish path for stable output across OSes."""
    return path.replace(os.sep, "/")


def collect_findings(root: str) -> tuple[list[Finding], list[str]]:
    """Scan root and return (findings, errors).

    Findings carry normalized paths so output is identical on Windows and POSIX.
    errors is a list of human readable messages for files that could not be
    scanned.
    """
    findings: list[Finding] = []
    errors: list[str] = []
    for file_path in _iter_python_files(root):
        file_findings, error = scan_file(file_path)
        display = _normalize_path(file_path)
        if error is not None:
            errors.append(f"{display}: {error}")
            continue
        for finding in file_findings:
            findings.append(
                Finding(
                    rule_id=finding.rule_id,
                    path=display,
                    line=finding.line,
                    col=finding.col,
                    snippet=finding.snippet,
                )
            )
    findings.sort(key=lambda f: f.sort_key())
    return findings, errors


def _cmd_scan(args: argparse.Namespace) -> int:
    findings, errors = collect_findings(args.path)
    for line in report.render_scan(findings):
        print(line)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    return 1 if findings else 0


def _cmd_report(args: argparse.Namespace) -> int:
    findings, errors = collect_findings(args.path)
    root_display = _normalize_path(args.path)
    for line in report.render_report(findings, root_display):
        print(line)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    return 1 if findings else 0
