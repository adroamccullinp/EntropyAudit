# Sample fixtures

These two files are hand authored test vectors. They are not production code and
were never taken from a real application. They exist so the scanner's true
positives and its false-positive rate can both be asserted in the test suite.

## vulnerable_auth.py

Constructed by hand to trigger every rule exactly once, except the nonce or IV
rule which is triggered twice (once for a fixed IV, once for a fixed nonce).
Each line carries a comment naming the rule it is meant to trip:

- EA001 predictable seed: `random.seed(1337)`
- EA003 time seed: `random.seed(time.time())`
- EA004 reused nonce or IV: a constant IV and a constant nonce
- EA005 fixed salt: a salt bound to a constant
- EA002 weak PRNG on security path: `random.getrandbits` assigned to a token name
- EA006 weak password hash: `hashlib.md5` assigned to a password hash name

## clean_auth.py

Constructed by hand to do the same work correctly, using `secrets` for tokens
and nonces, a fresh per password salt, and `hashlib.pbkdf2_hmac` for password
storage. It also contains a harmless `random.choice` call for a greeting to
prove that non-security uses of the random module are not flagged. This file
must produce zero findings.

# draft note 4
