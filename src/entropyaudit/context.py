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


