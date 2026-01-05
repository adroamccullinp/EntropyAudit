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
        return bool(origin and origin.split(".")[0] == "random")

    def _hashlib_call_name(self, func: ast.AST) -> str | None:
        """Return the hash algorithm name if func is a hashlib constructor.

        Handles hashlib.md5(...), hashlib.new("md5"), and from hashlib import md5.
        For hashlib.new the name comes from the first argument and is resolved by
        the caller.
        """
        dotted = _dotted_name(func)
        if dotted is None:
            return None
        head, _, leaf = dotted.rpartition(".")
        if head:
            canonical = self.imports.module_aliases.get(head, head)
            if canonical.split(".")[0] == "hashlib":
                return leaf
        else:
            origin = self.imports.name_aliases.get(dotted)
            if origin and origin.split(".")[0] == "hashlib":
                return origin.split(".")[-1]
        return None

    @staticmethod
    def _is_time_call(node: ast.AST) -> bool:
        """True when node is a call into the time module (time.time, etc.)."""
        if not isinstance(node, ast.Call):
            return False
        dotted = _dotted_name(node.func)
        if dotted is None:
            return False
        return dotted.split(".")[0] == "time" or dotted.startswith("time.")

    def visit_Call(self, node: ast.Call) -> None:
        self._check_seed(node)
        self._check_weak_prng(node)
        self._check_weak_hash(node)
        self.generic_visit(node)

    def _check_seed(self, node: ast.Call) -> None:
        is_seed = self._resolves_to_random_seed(node.func)
        is_ctor = self._resolves_to_random_ctor(node.func)
        if not (is_seed or is_ctor):
            return
        if not node.args:
            return
        arg = node.args[0]
        # EA003 time-seeded generator takes precedence over the generic
        # predictable seed rule because the exploit path is different.
        if self._is_time_call(arg):
            self._add("EA003", node)
        elif isinstance(arg, ast.Constant):
            self._add("EA001", node)

    def _check_weak_prng(self, node: ast.Call) -> None:
        callable_name = self._resolves_to_random(node.func)
        if callable_name is None:
            return
        # Fire only when the value produced by the random call flows into a
        # security-relevant identifier. Using file-level context alone would
        # flag safe, non-security uses of random (for example choosing a
        # greeting) inside a module that happens to import hashlib, so the
        # enclosing name is the deciding signal. The file secret context is
        # recorded and available for callers that want to weight confidence,
        # but it is not sufficient on its own.
        if self._enclosing_name_is_security(node):
            self._add("EA002", node)

    def _enclosing_name_is_security(self, node: ast.Call) -> bool:
        names = getattr(node, "_ea_target_names", None)
        if not names:
            return False
        return context.any_identifier_security_relevant(names)

    def _check_weak_hash(self, node: ast.Call) -> None:
        name = self._hashlib_call_name(node.func)
        algo = None
        if name == "new" and node.args and isinstance(node.args[0], ast.Constant):
            value = node.args[0].value
            if isinstance(value, str):
                algo = value.lower()
        elif name is not None and name.lower() in WEAK_HASHES:
            algo = name.lower()
        if algo is None or algo not in WEAK_HASHES:
            return
        # Only flag as password handling when a password-like name is in scope
        # for this call (target name carried by assignment, or the file clearly
        # handles secrets and a password term appears in the target).
        names = getattr(node, "_ea_target_names", []) or []
        password_terms = ("password", "passwd", "pwd", "credential")
        target_pw = any(
            any(term in context.normalize(n) for term in password_terms) for n in names
        )
        if target_pw:
            self._add("EA006", node)

    def visit_Assign(self, node: ast.Assign) -> None:
        target_names = _assign_target_names(node.targets)
        # Attach target names to any call in the value so nested checks can use
        # the enclosing identifier for security relevance.
        for call in _iter_calls(node.value):
            call._ea_target_names = target_names  # type: ignore[attr-defined]
        self._check_constant_binding(node, target_names)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        target_names = _assign_target_names([node.target])
        if node.value is not None:
            for call in _iter_calls(node.value):
                call._ea_target_names = target_names  # type: ignore[attr-defined]
            self._check_constant_binding(node, target_names)
        self.generic_visit(node)

    def _check_constant_binding(self, node: ast.AST, target_names: list[str]) -> None:
        value = getattr(node, "value", None)
        if not isinstance(value, ast.Constant):
            return
        if isinstance(value.value, bool) or value.value is None:
            return
        for name in target_names:
            normalized = context.normalize(name)
            if "nonce" in normalized or _is_iv_token(name):
                self._add("EA004", node)
                break
            if "salt" in normalized:
                self._add("EA005", node)
                break


def _is_iv_token(identifier: str) -> bool:
    spaced = _camel_to_spaces(identifier).replace("_", " ").lower().split()
    return "iv" in spaced


def _camel_to_spaces(identifier: str) -> str:
    import re

    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", identifier)


def _assign_target_names(targets: list[ast.AST]) -> list[str]:
    names: list[str] = []
    for target in targets:
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, ast.Attribute):
            names.append(target.attr)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                if isinstance(elt, ast.Name):
                    names.append(elt.id)
                elif isinstance(elt, ast.Attribute):
                    names.append(elt.attr)
    return names


def _iter_calls(value: ast.AST | None):
    if value is None:
        return
    for node in ast.walk(value):
        if isinstance(node, ast.Call):
            yield node
