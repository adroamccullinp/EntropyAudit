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
