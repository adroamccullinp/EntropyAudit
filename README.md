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
