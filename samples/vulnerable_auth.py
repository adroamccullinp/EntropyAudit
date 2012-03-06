"""Deliberately vulnerable sample for entropyaudit test vectors.

This file is a hand authored test vector, not production code. Every construct
below is here to trigger exactly one entropyaudit rule so the scanner and its
false-negative behaviour can be asserted. Do not copy any of this into real
software.
"""

import hashlib
import random
import time

