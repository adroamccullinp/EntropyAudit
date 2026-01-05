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


def identifier_is_security_relevant(identifier: str) -> bool:
    """True when identifier contains a security term.

    "iv" and "key" are short and could appear inside unrelated words, so they
    are matched as whole tokens split on underscores or camelCase boundaries,
    while longer terms match as substrings.
    """
    if not identifier:
        return False
    normalized = normalize(identifier)
    for term in SECURITY_TERMS:
        if len(term) <= 3:
            # Whole-token match for short terms to avoid false hits like
            # "give" matching "iv" or "monkey" matching "key".
            tokens = _split_tokens(identifier)
            if term in tokens:
                return True
        elif term in normalized:
            return True
    return False


def _split_tokens(identifier: str) -> set[str]:
    """Split an identifier into lowercase word tokens.

    Handles snake_case and camelCase. "session_ivValue" yields session, iv,
    value.
    """
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", identifier)
    spaced = spaced.replace("_", " ")
    return {w for w in _WORD.findall(spaced.lower())}


def any_identifier_security_relevant(identifiers: list[str]) -> bool:
    """True when any identifier in the list is security relevant."""
    return any(identifier_is_security_relevant(name) for name in identifiers)


def file_handles_secrets(imported_modules: set[str]) -> bool:
    """True when the file imports a module associated with handling secrets."""
    for mod in imported_modules:
        top = mod.split(".")[0]
        if top in SECURITY_IMPORTS:
            return True
    return False
