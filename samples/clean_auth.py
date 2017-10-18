"""Clean sample for entropyaudit test vectors.

This file handles secrets correctly and must produce zero entropyaudit
findings. It is a hand authored test vector used to prove the scanner does not
report false positives on safe code. It imports hashlib and secrets so the
file-level security context is active, which makes the zero-finding result a
meaningful negative test.
"""

import hashlib
import secrets

