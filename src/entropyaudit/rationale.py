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
        "seed offline and reconstruct every generated value. Do not seed "
        "security generators from time."
    ),
    "EA004": (
        "A nonce or initialization vector bound to a constant repeats on every "
        "encryption. For stream ciphers and counter modes, reusing a nonce with "
        "the same key lets an attacker xor two ciphertexts to cancel the "
        "keystream and recover plaintext. Nonces must be unique per message and "
        "IVs must be random."
    ),
    "EA005": (
        "A fixed salt means identical inputs hash to identical digests across "
        "all users and installs. This defeats the purpose of salting: an "
        "attacker can precompute one rainbow table and reuse it everywhere, and "
        "identical passwords become visibly identical. Generate a fresh random "
        "salt per value."
    ),
    "EA006": (
        "Fast hashes such as md5, sha1, and plain sha256 are designed for "
        "speed, so an attacker with the stored digest can try billions of "
        "password guesses per second on commodity hardware. Password storage "
        "needs a slow, salted function such as hashlib.scrypt, hashlib.pbkdf2_hmac, "
        "or a dedicated password hash."
    ),
}


def explain(rule_id: str) -> str:
    """Return the rationale text for rule_id, raising KeyError if unknown."""
    return RATIONALE[rule_id]
