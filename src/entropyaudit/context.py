"""Security-relevance context for entropyaudit.

A call to random.random is only worth flagging under EA002 when the surrounding
code is doing something security relevant. We decide that from two signals:

1. Which modules the file imports (a file that imports hashlib, hmac, secrets,
   or a cryptography style name is handling secrets).
2. The identifiers near the call site: names like token, secret, password,
   nonce, salt, key, iv, session, csrf, otp, and auth.

This module holds the vocabulary and the matching helpers. Keeping the naming
rules here means pyscan.py stays focused on tree walking.
"""

from __future__ import annotations

import re


# Substrings that mark an identifier as security relevant. Matched case
# insensitively against a normalized identifier (underscores removed).
SECURITY_TERMS = (
    "token",
    "secret",
    "password",
    "passwd",
    "nonce",
    "salt",
    "iv",
    "key",
    "session",
    "csrf",
    "xsrf",
    "otp",
    "auth",
    "cookie",
    "apikey",
    "credential",
    "cipher",
    "encrypt",
    "sign",
    "hmac",
)

# Modules whose presence in a file marks the file as handling secrets.
SECURITY_IMPORTS = (
    "hashlib",
    "hmac",
    "secrets",
    "ssl",
    "cryptography",
    "nacl",
    "Crypto",
    "jwt",
)

_WORD = re.compile(r"[a-z0-9]+")


def normalize(identifier: str) -> str:
    """Lowercase an identifier and strip underscores for term matching."""
    return identifier.replace("_", "").lower()


