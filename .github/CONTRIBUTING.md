# Contributing to EntropyAudit

Thanks for helping flag weak randomness before it ships.

## Ground rules

- **Standard library only.** Python 3.11, zero dependencies, zero network
  access. The tool reads source trees you already have on disk.
- **Findings need rationale.** Every new pattern must ship with a plain-language
  "why this matters" grounded in its CWE-style class, not just a regex.
- **No noise.** A pattern that fires on idiomatic non-security code more often
  than on real vulnerabilities does not belong in the table. Precision over
  recall.

## Workflow

1. Branch from `main` (`feat/<topic>` or `fix/<topic>`).
2. One behaviour per PR - small and reviewable.
3. Check locally:
   ```bash
   pip install -e .
   pytest
   python -m entropyaudit scan samples/vulnerable_auth.py
   ```
4. Open the PR describing *why*, not just *what*.

## Adding a pattern

New patterns live in `patterns.py`. Each needs:

- the AST/string matcher,
- a vulnerable and a clean sample (`samples/` follows this split),
- a test pair in `tests/`,
- severity tier + rationale text,
- an entry in the findings-by-class doc.

## Reporting issues

Use the bug template with the smallest source snippet that triggers a wrong
finding (or misses one). One file is almost always enough.

## Code style

- `pytest -q` stays green; report output is golden-tested (markdown + JSON).
- Finding IDs (EAxxx) are stable and never reused, even for retired patterns.
