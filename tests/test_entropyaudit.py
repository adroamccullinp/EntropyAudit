"""Tests for entropyaudit using the stdlib unittest framework."""

import io
import os
import sys
import unittest
import xml.dom.minidom
from contextlib import redirect_stdout

# Make the src layout importable without installation.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from entropyaudit import cli, patterns, rationale  # noqa: E402
from entropyaudit.pyscan import scan_source  # noqa: E402


SAMPLES = os.path.join(_ROOT, "samples")
VULN = os.path.join(SAMPLES, "vulnerable_auth.py")
CLEAN = os.path.join(SAMPLES, "clean_auth.py")


def _rule_ids(findings):
    return sorted(f.rule_id for f in findings)


class VulnerableSampleTests(unittest.TestCase):
    def setUp(self):
        findings, errors = cli.collect_findings(VULN)
