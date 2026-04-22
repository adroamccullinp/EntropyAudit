# Changelog

All notable changes to this project are documented here.

## [Unreleased]

## [0.5.0] - 2026-08-05

### Added
- `rationale` module: every finding carries a human-readable "why this matters"
  grounded in the pattern class, not a code reference.
- Findings-by-class chart in docs; sample tree extended with a clean auth module.

### Changed
- Context extraction keeps enclosing function and class, so report rows point
  at reviewable units instead of bare line numbers.

## [0.4.0] - 2024-07-30

### Added
- Nonce-hygiene patterns: reused counters, static IVs, `os.urandom` misuse.
- Severity tiers mapped from CWE-style pattern classes.

### Changed
- AST walk rewritten for 3.11 (`ast.Str` removal); string entropy scan now
  tokenises f-strings separately.

## [0.3.0] - 2022-11-02

### Added
- Context resolver: enclosing scope, decorators, and call-site detection.
- `report` renders markdown and JSON with identical finding sets.

## [0.2.0] - 2021-03-19

### Added
- Pattern table: hardcoded keys, weak PRNGs (`random` for secrets), short
  salts, IV reuse.
- Exit codes for CI gating (fail on high severity).

## [0.1.0] - 2019-09-08

### Added
- First CLI: `entropyaudit scan <tree>` with per-file findings.
- Shannon entropy scan for literal strings.

## [0.0.1] - 2018-05-14

### Added
- Prototype: single-file scanner flagging `random.random()` used as a secret.

# draft note 105
