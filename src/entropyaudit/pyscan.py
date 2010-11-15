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
        findings = scan_source(source, path)
    except SyntaxError as exc:
        return [], f"syntax error at line {exc.lineno}"
    return findings, None


def _collect_imports(tree: ast.AST) -> _ImportInfo:
    info = _ImportInfo()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                info.module_aliases[local] = alias.name
                info.imported_modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module:
                info.imported_modules.add(module)
            for alias in node.names:
                local = alias.asname or alias.name
                info.name_aliases[local] = f"{module}.{alias.name}" if module else alias.name
    return info


def _dotted_name(node: ast.AST) -> str | None:
    """Return a dotted name for an attribute or name node, else None."""
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _snippet(source_line: str) -> str:
    return source_line.strip()


class _Visitor(ast.NodeVisitor):
    """Walks a module tree recording findings."""

    def __init__(self, path: str, imports: _ImportInfo) -> None:
        self.path = path
        self.imports = imports
        self.findings: list[Finding] = []
        self.file_secret_context = context.file_handles_secrets(imports.imported_modules)

    def _add(self, rule_id: str, node: ast.AST) -> None:
        self.findings.append(
            Finding(
                rule_id=rule_id,
                path=self.path,
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                snippet=self._node_snippet(node),
            )
        )

    def _node_snippet(self, node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return ""

    def _resolves_to_random(self, func: ast.AST) -> str | None:
        """If func is a call into the random module, return the callable name.

        Handles: import random; random.random(), the aliased form, and
        from random import randint style names. Returns the leaf callable name
        (for example "randint") or None.
        """
        dotted = _dotted_name(func)
        if dotted is None:
            return None
        head, _, leaf = dotted.rpartition(".")
        if head:
            canonical = self.imports.module_aliases.get(head, head)
            if canonical.split(".")[0] == "random" and leaf in RANDOM_CALLABLES:
                return leaf
            # random.Random().method style is covered by the constructor check.
        else:
            # bare name imported via "from random import randint"
            origin = self.imports.name_aliases.get(dotted)
            if origin and origin.split(".")[0] == "random":
                leaf_name = origin.split(".")[-1]
                if leaf_name in RANDOM_CALLABLES:
                    return leaf_name
        return None

    def _resolves_to_random_seed(self, func: ast.AST) -> bool:
        dotted = _dotted_name(func)
        if dotted is None:
            return False
        head, _, leaf = dotted.rpartition(".")
        if leaf != "seed":
            return False
        if head:
            canonical = self.imports.module_aliases.get(head, head)
            return canonical.split(".")[0] == "random"
        origin = self.imports.name_aliases.get(dotted)
        return bool(origin and origin.split(".")[0] == "random")

    def _resolves_to_random_ctor(self, func: ast.AST) -> bool:
        """True when func is random.Random or an imported Random constructor."""
        dotted = _dotted_name(func)
        if dotted is None:
            return False
        head, _, leaf = dotted.rpartition(".")
        if leaf != "Random":
            return False
        if head:
            canonical = self.imports.module_aliases.get(head, head)
            return canonical.split(".")[0] == "random"
        origin = self.imports.name_aliases.get(dotted)
