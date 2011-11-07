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

