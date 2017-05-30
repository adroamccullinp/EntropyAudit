"""Per-rule exploitability rationale for entropyaudit.

The report must never degrade into a checkbox list, so every rule carries a
written explanation of why the pattern is exploitable and what an attacker gains
from it. These strings are the source of that text.
"""

from __future__ import annotations


# One entry per rule id in patterns.RULES. Each explains the concrete
