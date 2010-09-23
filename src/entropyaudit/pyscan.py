"""AST walkers for entropyaudit.

The scanner parses each Python file with the stdlib ast module and walks it with
NodeVisitor subclasses. It records findings as Finding objects. Nothing here
touches the network or the clock; parsing is fully static.

Detection summary:

- EA001 predictable seed: random.seed(<constant>) or Random(<constant>).
- EA002 weak PRNG on security path: a random.* call whose result feeds a
  security-relevant name, or that sits in a file handling secrets.
- EA003 time seed: random.seed(time.time()) or seeding from a time.* call.
- EA004 reused nonce or IV: a module-level assignment to a nonce/iv name bound
  to a constant bytes or str literal.
- EA005 fixed salt: a salt-named target bound to a constant literal.
- EA006 weak password hash: hashlib.md5 / sha1 / sha256 (and new("md5") style)
  used where a password-related identifier is in scope.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from . import context


WEAK_HASHES = {"md5", "sha1", "sha256", "sha224"}
RANDOM_CALLABLES = {
    "random",
    "randint",
    "randrange",
    "choice",
    "choices",
    "sample",
    "shuffle",
    "uniform",
