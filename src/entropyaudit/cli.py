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
