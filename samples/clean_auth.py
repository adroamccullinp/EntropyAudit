"""Clean sample for entropyaudit test vectors.

This file handles secrets correctly and must produce zero entropyaudit
findings. It is a hand authored test vector used to prove the scanner does not
report false positives on safe code. It imports hashlib and secrets so the
file-level security context is active, which makes the zero-finding result a
meaningful negative test.
"""

import hashlib
import secrets


def make_session_token():
    # Correct: cryptographically strong token from the secrets module.
    session_token = secrets.token_hex(32)
    return session_token


def generate_nonce():
    # Correct: a fresh random nonce per call, not a constant.
    message_nonce = secrets.token_bytes(12)
    return message_nonce


def store_password(password):
    # Correct: a fresh random salt per password and a slow salted hash.
    password_salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), password_salt, 200000
    )
    return password_salt, password_hash


def pick_greeting():
    # Non-security use of random is fine and must not be flagged. This name has
    # no security term and the value never guards access.
    import random

    greetings = ["hello", "hi", "welcome"]
    return random.choice(greetings)

# draft note 125
