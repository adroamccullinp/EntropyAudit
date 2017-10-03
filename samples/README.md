# Sample fixtures

These two files are hand authored test vectors. They are not production code and
were never taken from a real application. They exist so the scanner's true
positives and its false-positive rate can both be asserted in the test suite.

## vulnerable_auth.py

Constructed by hand to trigger every rule exactly once, except the nonce or IV
rule which is triggered twice (once for a fixed IV, once for a fixed nonce).
Each line carries a comment naming the rule it is meant to trip:

- EA001 predictable seed: `random.seed(1337)`
