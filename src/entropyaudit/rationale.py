"""Per-rule exploitability rationale for entropyaudit.

The report must never degrade into a checkbox list, so every rule carries a
written explanation of why the pattern is exploitable and what an attacker gains
from it. These strings are the source of that text.
"""

from __future__ import annotations


# One entry per rule id in patterns.RULES. Each explains the concrete
# exploitability, not just the label. Kept in plain sentences, no em dashes.
RATIONALE = {
    "EA001": (
        "A generator seeded with a literal constant produces the same sequence "
        "on every run. An attacker who knows or guesses the seed can reproduce "
        "every value the program will emit, including tokens, IDs, and choices "
        "meant to be unguessable. Seeding must come from an unpredictable "
        "source, and for security values use the secrets module."
    ),
    "EA002": (
