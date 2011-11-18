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
        self.assertEqual(errors, [], "vulnerable sample should scan cleanly")
        self.findings = findings

    def test_vulnerable_sample_has_findings(self):
        self.assertTrue(self.findings, "vulnerable sample must produce findings")

    def test_expected_rule_coverage(self):
        ids = set(f.rule_id for f in self.findings)
        for expected in ("EA001", "EA002", "EA003", "EA004", "EA005", "EA006"):
            self.assertIn(expected, ids, f"{expected} should fire on the vector")

    def test_nonce_and_iv_both_flagged(self):
        ea004 = [f for f in self.findings if f.rule_id == "EA004"]
