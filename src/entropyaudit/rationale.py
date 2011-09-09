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
        "The random module is a Mersenne Twister, not a cryptographic "
        "generator. After observing a few hundred outputs an attacker can "
        "recover the internal state and predict all future outputs. When the "
        "value guards access, such as a token, password, session id, salt, or "
        "nonce, use secrets or os.urandom instead."
    ),
    "EA003": (
        "Seeding from the current time makes the sequence depend only on when "
        "the program started. The search space is small, often a few million "
        "values across a plausible window, so an attacker can brute force the "
