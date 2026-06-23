# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Initial repository scaffolding: `README.md`, `.gitignore`.
- `CLAUDE.md` defining the three project principles (scalable, traceable, debuggable)
  and the non-negotiable maintained-markdown discipline.
- `.claude/` project settings directory.
- Maintained docs: `CHANGELOG.md`, `docs/DECISIONS.md`, `docs/CONTROLS.md`,
  `docs/THREAT-MODEL.md`.
- `reports/` directory for generated audit artifacts (git-ignored output).
- **Package skeleton & engine (Phase 0):** the `auditor` package with `models` (Control /
  Finding / CheckResult / AuditReport / Severity / Status), the `Host` abstraction
  (`LocalHost` + `FakeHost`), a self-registering control `registry` with the `@control`
  decorator, the discover-and-run `engine`, the `argparse` CLI (`audit` / `fix`), and
  `console` + `json` reporters. `python -m auditor audit` runs end-to-end.
- `pyproject.toml` (stdlib-only runtime; `ruff` + `pytest` dev extras) and a `tests/` suite
  covering the engine, registry, and reporters (8 tests, all OS-independent via `FakeHost`).
- ADR-0004: checks read the system through an injected `Host`, never directly.
- **First control (Phase 1):** CIS 5.2.8 — SSH `PermitRootLogin no`
  (`auditor/checks/ssh_permit_root_login.py`), with a shared `_ssh` helper that resolves
  sshd's effective config via `sshd -T` and falls back to parsing `/etc/ssh/sshd_config`
  (first-value-wins, per `sshd_config(5)`). 7 tests cover pass/fail/skip and the fallback.

### Changed
- Rewrote `README.md` as a product-facing project showcase (what the tool does, quick start,
  example report, design, roadmap) instead of internal CV-planning notes.

### Notes
- No controls implemented yet. See `docs/CONTROLS.md` for the planned catalogue.
