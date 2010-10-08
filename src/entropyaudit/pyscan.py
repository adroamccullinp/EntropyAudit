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
    "getrandbits",
    "randbytes",
}


@dataclass(frozen=True)
class Finding:
    """A single detected issue in a source file."""

    rule_id: str
    path: str
    line: int
    col: int
    snippet: str

    def sort_key(self) -> tuple:
        return (self.path, self.line, self.col, self.rule_id)


@dataclass
class _ImportInfo:
    """Tracks how randomness and hashing modules were imported in a file."""

    # Maps a local alias back to the canonical dotted module name.
    module_aliases: dict = field(default_factory=dict)
    # Maps a local name bound by "from x import y as z" to "x.y".
    name_aliases: dict = field(default_factory=dict)
    # All top-level modules imported, for file-level security context.
    imported_modules: set = field(default_factory=set)


def scan_source(source: str, path: str) -> list[Finding]:
    """Parse source and return findings for the given display path.

    A file that fails to parse yields no findings; the caller is told through
    the returned parse error channel in scan_file.
    """
    tree = ast.parse(source)
    imports = _collect_imports(tree)
    visitor = _Visitor(path=path, imports=imports)
    visitor.visit(tree)
    findings = visitor.findings
    findings.sort(key=lambda f: f.sort_key())
    return findings


def scan_file(path: str) -> tuple[list[Finding], str | None]:
    """Scan a file on disk.

    Returns (findings, error). error is None on success, otherwise a short
    message describing why the file could not be scanned.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
    except OSError as exc:
        return [], f"cannot read: {exc.strerror or exc}"
    try:
