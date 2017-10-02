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
        self.assertEqual(len(ea004), 2, "both the IV and nonce constants fire EA004")

    def test_total_count_is_seven(self):
        self.assertEqual(len(self.findings), 7)


class CleanSampleTests(unittest.TestCase):
    def test_clean_sample_zero_findings(self):
        findings, errors = cli.collect_findings(CLEAN)
        self.assertEqual(errors, [])
        self.assertEqual(
            findings, [], f"clean sample must be free of findings, got {_rule_ids(findings)}"
        )

    def test_non_security_random_not_flagged(self):
        # random.choice for a greeting must not trip EA002.
        source = (
            "import random\n"
            "def pick():\n"
            "    greeting = random.choice(['hi', 'hello'])\n"
            "    return greeting\n"
        )
        findings = scan_source(source, "inline.py")
        self.assertEqual(findings, [])


class DetectionUnitTests(unittest.TestCase):
    def test_constant_seed(self):
        findings = scan_source("import random\nrandom.seed(42)\n", "s.py")
        self.assertEqual(_rule_ids(findings), ["EA001"])

    def test_time_seed(self):
        source = "import random\nimport time\nrandom.seed(time.time())\n"
        findings = scan_source(source, "s.py")
        self.assertEqual(_rule_ids(findings), ["EA003"])

    def test_security_named_target_triggers_ea002(self):
        source = (
            "import random\n"
            "auth_token = random.getrandbits(64)\n"
        )
        findings = scan_source(source, "s.py")
        self.assertEqual(_rule_ids(findings), ["EA002"])

    def test_fixed_salt(self):
        findings = scan_source("password_salt = b'abc'\n", "s.py")
        self.assertEqual(_rule_ids(findings), ["EA005"])

    def test_constant_nonce(self):
        findings = scan_source("message_nonce = b'abc'\n", "s.py")
        self.assertEqual(_rule_ids(findings), ["EA004"])

    def test_weak_password_hash(self):
        source = (
            "import hashlib\n"
            "password_hash = hashlib.md5(b'x').hexdigest()\n"
        )
        findings = scan_source(source, "s.py")
        self.assertEqual(_rule_ids(findings), ["EA006"])

    def test_hashlib_new_string_form(self):
        source = (
            "import hashlib\n"
            "password_hash = hashlib.new('sha1', b'x')\n"
        )
        findings = scan_source(source, "s.py")
        self.assertEqual(_rule_ids(findings), ["EA006"])

    def test_aliased_random_import(self):
        source = (
            "import random as rng\n"
            "session_key = rng.randint(0, 9)\n"
        )
        findings = scan_source(source, "s.py")
        self.assertEqual(_rule_ids(findings), ["EA002"])

    def test_bool_and_none_not_flagged_as_nonce(self):
        # A nonce name bound to None or a bool is not a constant secret.
        findings = scan_source("nonce = None\nuse_iv = True\n", "s.py")
        self.assertEqual(findings, [])
