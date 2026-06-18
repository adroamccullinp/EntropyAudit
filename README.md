<p align="center">
  <img src="docs/assets/logo.svg" width="340"
       alt="Wordmark reading EntropyAudit, with entropy in dark ink and audit in amber, split at the compound word boundary">
</p>

<p align="center"><em>Static auditor for randomness and nonce hygiene in Python source trees.</em></p>

---

| At a glance             | Value                                                        |
|-------------------------|--------------------------------------------------------------|
| Language                | Python 3.11 (tested on CPython 3.11.6)                       |
| Dependencies            | None. Standard library only.                                 |
| Network access          | None. No socket, no HTTP, no telemetry anywhere in the code. |
| Analysis type           | Static. Parses with the stdlib `ast` module, no execution.   |
| Rules                   | Six: EA001 through EA006.                                    |
| Findings on the bundled sample | 7 (6 high, 1 medium) on `samples/vulnerable_auth.py`. |
| Exit code on findings   | 1 (0 when clean, 2 on a usage error).                        |
| Tests                   | 23 tests, stdlib `unittest`, all passing.                    |

# EntropyAudit

EntropyAudit reads Python source and reports where a program leans on
randomness that is not random enough to hold up security. It parses each file
with the standard library `ast` module and looks for predictable seeds, use of
the `random` module where `secrets` is required, time seeded generators, reused
nonce or IV constants, fixed salts, and weak hash choices for password handling.
Every finding carries a written exploitability rationale, so the report explains
why a pattern is dangerous instead of listing bare codes.

## Why randomness bugs survive review

Randomness failures are quiet. A call to `random.getrandbits(128)` looks like it
produces a large unpredictable number, and it does produce a large number. The
problem is that `random` is a Mersenne Twister: after an observer collects a few
hundred outputs, the internal state can be recovered and every future output
predicted. Nothing in the line reads as wrong, the code runs, the tests pass,
and the token looks fine in a log. The defect only becomes visible when someone
attacks it.

The same quietness applies to the other patterns this tool checks. A seed of
`1337` produces the same stream on every run. A nonce assigned to a constant
repeats on every encryption. A salt hard coded once is shared by every user. A
password hashed with `md5` is one commodity GPU away from a wordlist. Each of
these is a single line that behaves correctly in a demo and fails only against
an adversary who is not in the room during code review.

EntropyAudit exists to make these lines visible before that adversary finds
them. It does not prove exploitability in a given deployment; it flags the
pattern and explains the exploit path so a reviewer can decide. The written
rationale is the point: a bare "CWE-338" tells a reviewer nothing they can act
on, while "Mersenne Twister state can be recovered from a few hundred outputs,
so use `secrets`" tells them exactly what to change and why.

## Install

Install from the project directory:

```
pip install .
```

Or run it in place without installing. On Windows PowerShell:

```
$env:PYTHONPATH="src"
python -m EntropyAudit scan samples
```

On a POSIX shell:

```
PYTHONPATH=src python -m EntropyAudit scan samples
```

Installing also registers an `EntropyAudit` console script through the
`[project.scripts]` entry in `pyproject.toml`, so `EntropyAudit scan samples`
works once the package is on the path.

## Commands

Four subcommands. Each takes a file or a directory; a directory is walked in
sorted, deterministic order and every `.py` file under it is scanned.

| Command   | Argument    | What it prints                                                 |
|-----------|-------------|----------------------------------------------------------------|
| `scan`    | path        | One block per finding: location, category, code, and rationale.|
| `report`  | path        | A grouped report: counts by class, then findings under each.   |
| `explain` | rule id (optional) | The rationale for one rule, or all six when omitted.    |
| `version` | none        | The package version string.                                    |

## The rule set

Six rules, EA001 through EA006. Each entry below states what the rule matches in
the AST, the CWE class it maps to, why the pattern is exploitable, and a short
before and after pair. The severity and CWE mapping come from `patterns.py`; the
rationale text comes from `rationale.py`.

### EA001: predictable seed passed to a random generator

Matches `random.seed(<constant>)` or `Random(<constant>)` where the argument is
a literal constant. Class: Use of Insufficiently Random Values, CWE-330,
severity high.

Exploitability: a generator seeded with a literal produces the same sequence on
every run. An attacker who knows or guesses the seed reproduces every value the
program emits, including tokens, IDs, and choices meant to be unguessable.

```python
random.seed(1337)                  # before
token = random.getrandbits(128)
token = secrets.token_bytes(16)    # after (import secrets)
```

### EA002: random module used on a security-relevant path

Matches a call into the `random` module (`random`, `randint`, `randrange`,
`choice`, `choices`, `sample`, `shuffle`, `uniform`, `getrandbits`, `randbytes`)
whose result flows into a security relevant identifier. Class: Use of
Cryptographically Weak PRNG, CWE-338, severity high.

Exploitability: `random` is a Mersenne Twister, not a cryptographic generator.
After observing a few hundred outputs an attacker can recover the internal state
and predict all future outputs.

```python
session_token = random.getrandbits(128)   # before
session_token = secrets.token_hex(16)      # after (import secrets)
```

### EA003: generator seeded from wall-clock time

Matches `random.seed(time.time())` or seeding from any `time.*` call. This rule
takes precedence over EA001 because the exploit path is different: the seed is
not a fixed literal but a small, guessable window. Class: Predictable Seed in
PRNG, CWE-337, severity high.

Exploitability: seeding from the current time makes the sequence depend only on
when the program started. The search space is often a few million values across
a plausible window, so an attacker can brute force the seed offline.

```python
random.seed(time.time())          # before
rng = secrets.SystemRandom()      # after (import secrets)
```

### EA004: reused nonce or IV bound to a constant

Matches a module-level assignment to a `nonce` or `iv` named target bound to a
constant `bytes` or `str` literal. `iv` is matched as a whole token so it does
not fire on words like "give". Class: Reusing a Nonce or Key Pair in Encryption,
CWE-323, severity high.

Exploitability: a nonce or IV bound to a constant repeats on every encryption.
For stream ciphers and counter modes, reusing a nonce with the same key lets an
attacker xor two ciphertexts to cancel the keystream and recover plaintext.

```python
message_nonce = b"fixed-nonce-value"   # before
message_nonce = os.urandom(12)         # after (import os)
```

### EA005: fixed salt used for key derivation or hashing

Matches a `salt` named target bound to a constant literal. Class: Use of a
One-Way Hash with a Predictable Salt, CWE-760, severity medium.

Exploitability: a fixed salt means identical inputs hash to identical digests
across all users and installs. An attacker can precompute one rainbow table and
reuse it everywhere, and identical passwords become visibly identical.

```python
password_salt = b"static-salt-1234"        # before
password_salt = secrets.token_bytes(16)    # after (import secrets)
```

### EA006: weak hash used for password handling

Matches `hashlib.md5`, `sha1`, `sha256`, or `sha224` (including the
`hashlib.new("md5")` string form) when a password-like identifier
(`password`, `passwd`, `pwd`, `credential`) is the assignment target. Class: Use
of Password Hash With Insufficient Computational Effort, CWE-916, severity high.

Exploitability: fast hashes are designed for speed, so an attacker with the
stored digest can try billions of guesses per second on commodity hardware.
Password storage needs a slow, salted function.

```python
# before
password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
# after
password_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
```

## Deciding what is security relevant

The `random` module is not always a problem, and this is where EntropyAudit
tries hardest not to cry wolf. EA002 uses two signals, both defined in
`context.py`.

The import based test asks which modules the file imports. A file that imports
`hashlib`, `hmac`, `secrets`, `ssl`, `cryptography`, `nacl`, `Crypto`, or `jwt`
is handling secrets. This file-level context is computed once per file and
recorded, and it is available to weight confidence.

The identifier based test asks whether the value produced by a `random` call
flows into a security relevant name. The vocabulary is: `token`, `secret`,
`password`, `passwd`, `nonce`, `salt`, `iv`, `key`, `session`, `csrf`, `xsrf`,
`otp`, `auth`, `cookie`, `apikey`, `credential`, `cipher`, `encrypt`, `sign`,
and `hmac`. Long terms match as substrings; short terms (`iv`, `key`, `otp`) are
matched as whole tokens split on underscores and camelCase boundaries, so
`monkey` does not match `key` and `give` does not match `iv`.

The identifier is the deciding signal for EA002, not the file context. A module
that imports `hashlib` for one function and also picks a greeting with
`random.choice` should not have that greeting flagged. Because the enclosing
assignment target (`greeting`) carries no security term, the harmless
`random.choice(['hi', 'hello'])` is left alone. That is precisely the case the
clean sample and a dedicated unit test exercise.

## False positives and false negatives

Stated plainly, because a scanner that hides its blind spots is worse than one
that names them.

False positives are minimised by requiring a security relevant identifier for
EA002 and a constant literal binding for EA004 and EA005. On the bundled clean
sample, which imports `hashlib` and `secrets` and uses `random.choice` for a
greeting, the tool reports zero findings.

False negatives are the deliberate cost of that choice. EA002 depends on
identifier naming, so a value stored under a non descriptive name
(`x = random.random()` later used as a token) is missed. There is no data flow
analysis across a rename, and constant detection only sees direct literal
bindings, so a constant assembled at runtime is not folded.

## A worked scan of the bundled samples

The `samples/` directory holds two hand authored test vectors:
`vulnerable_auth.py`, built to trip every rule (EA004 twice, once for a fixed IV
and once for a fixed nonce), and `clean_auth.py`, built to do the same work
correctly and produce nothing.

The following was captured by running the command shown against `samples/` in
this repository. It is pasted verbatim.

```
$ python -m EntropyAudit report samples
EntropyAudit report for samples
===============================

findings by class:
      1  Predictable Seed in PRNG
      2  Reusing a Nonce or Key Pair in Encryption
      1  Use of Cryptographically Weak PRNG
      1  Use of Insufficiently Random Values
      1  Use of Password Hash With Insufficient Computational Effort
      1  Use of a One-Way Hash with a Predictable Salt

Predictable Seed in PRNG
    samples/vulnerable_auth.py:18:0 [high] EA003 Generator seeded from wall-clock time

Reusing a Nonce or Key Pair in Encryption
    samples/vulnerable_auth.py:21:0 [high] EA004 Reused nonce or IV bound to a constant
    samples/vulnerable_auth.py:24:0 [high] EA004 Reused nonce or IV bound to a constant

Use of Cryptographically Weak PRNG
    samples/vulnerable_auth.py:33:20 [high] EA002 random module used on a security-relevant path

Use of Insufficiently Random Values
    samples/vulnerable_auth.py:15:0 [high] EA001 Predictable seed passed to random generator

Use of Password Hash With Insufficient Computational Effort
    samples/vulnerable_auth.py:39:20 [high] EA006 Weak hash used for password handling

Use of a One-Way Hash with a Predictable Salt
    samples/vulnerable_auth.py:27:0 [medium] EA005 Fixed salt used for key derivation or hashing

7 findings: 6 high, 1 medium, 0 low
```

Seven findings across six classes, with the reused nonce or key class carrying
two. The chart below is drawn from those same counts.

![Bar chart of findings by class. Reusing a nonce or key pair has two findings; the other five classes have one each. Total seven.](docs/assets/findings-by-class.svg)

The clean sample produces nothing:

```
$ python -m EntropyAudit scan samples/clean_auth.py
0 findings
```

## Output format

The `scan` view prints one block per finding, then a summary line. Each field is
fixed, so the format can be treated as a contract.

| Line             | Format                                                     | Source        |
|------------------|------------------------------------------------------------|---------------|
| header           | `path:line:col: SEVERITY RULEID Title`                     | `report.py`   |
| category         | `    category: <CWE class> (<CWE id>)`                     | `patterns.py` |
| code             | `    code: <the offending source, unparsed from the AST>` | `pyscan.py`   |
| why              | `    why: <exploitability rationale>`                      | `rationale.py`|
| summary          | `N findings: H high, M medium, L low` (or `0 findings`)   | `report.py`   |

The `report` view prints a header, a `findings by class:` block with a count per
category, then each finding grouped under its category using the compact form
`path:line:col [severity] RULEID Title`, and finally the same summary line.
Findings are sorted by path, line, column, then rule id before rendering, so the
same input tree always yields byte identical output and diffs cleanly in git.

## Exit codes

| Code | Meaning                                                        |
|------|----------------------------------------------------------------|
| 0    | Clean. No findings.                                            |
| 1    | Findings present. `scan` and `report` return 1 when any fire. |
| 2    | Usage error. Unknown rule id to `explain`, or argparse error. |

These were confirmed in this session: `scan` on the vulnerable sample exited 1,
`scan` on the clean sample exited 0, and `version` exited 0.

## Using it in CI

Because a non-zero exit means findings, a scan can gate a pipeline directly. In
a POSIX CI step:

```
PYTHONPATH=src python -m EntropyAudit scan src || exit 1
```

The job fails when any finding fires and passes when the tree is clean. To
inspect changes over time, run `report` on two revisions and diff the output;
the sorted, deterministic rendering means the diff shows only real changes in
findings, not reordering noise.

## Limitations

- Static analysis cannot see runtime seeding. EntropyAudit reads the source
  tree; it never executes the code, so a seed computed at runtime from a value
  it cannot fold is invisible to it.
- It only reads Python. Files are parsed with the stdlib `ast` module, so a
  weak construct written in another language, or in a string passed to `eval`,
  is out of scope.
- It is name and pattern based, not data flow based. A weak value stored under a
  non descriptive name and later used as a secret is missed by design.
- Constant detection for nonces, IVs, and salts looks at direct literal
  bindings. A constant assembled from other constants at runtime is not folded.
- It reads one file at a time and does not resolve imports across modules.
- It reports the presence of a risky pattern. It does not prove the code is
  exploitable in a given deployment.

## Design decisions

Why `ast` rather than regex. A regex over source text cannot tell
`random.seed(x)` where `random` is the standard library module from a local
variable named `random`, cannot follow `import random as rng`, and cannot know
whether `md5(...)` came from `hashlib`. EntropyAudit resolves aliases and
`from x import y` forms by collecting imports first, then walking the parsed tree
with `NodeVisitor` subclasses. That is why the aliased-import and
`hashlib.new("sha1")` cases have real tests: they are exactly the cases a regex
would get wrong.

Why rationale text is mandatory per rule. A finding that says only "EA338" or
"CWE-338" gives a reviewer a label, not a decision. The report walks
`rationale.py`, which holds one explanation per rule id, and a test asserts every
rule has non-empty rationale text and that none of it contains an em dash. The
rationale is treated as part of the rule, not documentation bolted on after, so
the report can never degrade into a bare checklist.

## Repository layout

```
EntropyAudit/
  pyproject.toml            build config, console script, package metadata
  README.md                 this file
  CHANGELOG.md              release notes
  LICENSE                   MIT
  .gitignore                ignore rules
  src/EntropyAudit/
    __init__.py             package marker and __version__
    __main__.py             entry point so `python -m EntropyAudit` runs
    cli.py                  argparse subcommands, file walking, exit codes
    pyscan.py               ast.NodeVisitor walkers that record findings
    patterns.py             rule definitions: id, title, severity, CWE class
    context.py              decides whether a call site is security relevant
    rationale.py            the per rule exploitability explanation text
    report.py               line oriented, deterministic rendering
  samples/
    README.md               describes the two test vectors
    vulnerable_auth.py      one construct per rule, EA004 twice
    clean_auth.py           the same work done correctly, zero findings
  tests/
    test_entropyaudit.py    stdlib unittest suite
  docs/assets/
    logo.svg                the wordmark shown above
    findings-by-class.svg   the bar chart of findings by class
```

## Glossary

| Term       | Meaning in this tool                                                        |
|------------|------------------------------------------------------------------------------|
| PRNG       | Pseudo-random number generator. `random` is one; it is not cryptographic.    |
| CSPRNG     | Cryptographically secure PRNG, such as `secrets` or `os.urandom`.            |
| Seed       | The starting value of a PRNG. A fixed or guessable seed fixes the sequence.  |
| Nonce      | A number used once. Reusing one with a key breaks stream and counter modes.  |
| IV         | Initialization vector. Like a nonce, must be unpredictable and not reused.   |
| Salt       | Random per-value input to a hash. A fixed salt defeats the point of salting. |
| Mersenne Twister | The algorithm behind `random`; its state is recoverable from outputs.  |
| CWE        | Common Weakness Enumeration; the class label attached to each rule.          |
| Finding    | One detected issue: rule id, path, line, column, and the offending code.     |

## Verification

The test suite uses the standard library `unittest` framework. Run it from the
project directory:

```
$ PYTHONPATH=src python -m unittest discover -s tests -v
```

In this session that run reported:

```
Ran 23 tests in 0.011s

OK
```

The 23 tests cover: every rule firing on the vulnerable sample; the total count
of seven; both EA004 findings; zero findings on the clean sample; that a
non-security `random.choice` is not flagged; the constant seed, time seed,
security-named target, fixed salt, constant nonce, weak password hash, and
`hashlib.new` string forms individually; aliased `import random as rng`; that a
nonce bound to `None` or a bool is not flagged; that every rule has rationale
text with no em dash; that `scan` is deterministic across two runs; the exit
codes for clean, version, and an unknown rule; and that the shipped SVGs parse
as XML and carry no blur, shadow, or turbulence filters.

## Roadmap

No dates are promised. Possible future work, in rough order of value:

- Track a weak value across a single-function assignment chain to reduce the
  EA002 false negative on non descriptive names.
- Fold constants assembled from other module-level constants so EA004 and EA005
  catch indirect bindings.
- Add a machine-readable output mode (JSON) alongside the current text views.
- Allow a per-project allowlist for identifiers that look security relevant but
  are not.

## License

MIT. See [LICENSE](LICENSE).

# draft note 10
