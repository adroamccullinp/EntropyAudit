"""Deliberately vulnerable sample for entropyaudit test vectors.

This file is a hand authored test vector, not production code. Every construct
below is here to trigger exactly one entropyaudit rule so the scanner and its
false-negative behaviour can be asserted. Do not copy any of this into real
software.
"""

import hashlib
import random
import time


# EA001: generator seeded from a literal constant.
random.seed(1337)

# EA003: generator seeded from wall-clock time.
random.seed(time.time())

# EA004: an IV bound to a constant, reused on every encryption.
static_iv = b"0000000000000000"

# EA004: a nonce bound to a constant.
message_nonce = b"fixed-nonce-value"

# EA005: a fixed salt used for hashing.
password_salt = b"static-salt-1234"


def make_session_token():
    # EA002: the random module used to build a security token. Predictable
    # because Mersenne Twister state can be recovered from outputs.
    session_token = random.getrandbits(128)
    return session_token


def store_password(password):
    # EA006: a fast hash used for password storage.
    password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
    return password_hash

# draft note 46
