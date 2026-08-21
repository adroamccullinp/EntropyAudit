# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | yes       |
| < 0.5   | no        |

## Reporting a vulnerability

EntropyAudit scans local Python trees offline, so the surface is narrow:

- unbounded memory on adversarial source files (deeply nested ASTs, huge
  string literals),
- catastrophic backtracking in pattern regexes,
- report injection: source-derived strings must be escaped in markdown/JSON
  output so a crafted identifier cannot smuggle markup into the report.

Please do **not** open a public issue for these. Contact the repository owner
through the profile with:

1. The affected version (`entropyaudit version` or the commit SHA).
2. The smallest input file that triggers the behaviour.
3. Expected vs. actual behaviour.

You will get an acknowledgement within a week. Fixes land in the next minor
release and the reporter is credited in the changelog unless they prefer
otherwise.

## Scope

- `pyscan.py` / `context.py` - untrusted input, primary focus.
- `patterns.py` - matcher behaviour.
- `report.py` - escaping of source-derived strings in output.
