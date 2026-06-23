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
- **First control (Phase 1):** CIS 5.2.7 — SSH `PermitRootLogin no`
  (`auditor/checks/ssh_permit_root_login.py`), with a shared `_ssh` helper that resolves
  sshd's effective config via `sshd -T` and falls back to parsing `/etc/ssh/sshd_config`
  (first-value-wins, per `sshd_config(5)`). 7 tests cover pass/fail/skip and the fallback.
- **Reporters (Phase 2):** `markdown` (score + per-severity summary + findings tables +
  remediation checklist) and self-contained `html` (inline CSS, HTML-escaped) reporters,
  alongside the existing `console` and `json`. Shared `_common` helper guarantees identical
  grouping/ordering across formats. `--report md` is an alias for markdown; markdown/html
  default their output to `reports/<host>-<date>.<ext>`. Reporter tests extended to 11.
- **Seed control catalogue completed (Phase 3):** the remaining 9 controls, mapped to
  CIS Ubuntu 22.04 LTS v1.0.0 (each with a test and a THREAT-MODEL rationale):
  - `5.2-BP` SSH key-only auth (`PasswordAuthentication no`) — best practice beyond CIS,
    BSI-aligned, labelled honestly as such.
  - `5.2.13` SSH strong ciphers only (fails on CBC/arcfour/3des).
  - `5.4.1` password minimum length ≥ 14 (pam_pwquality).
  - `4.1.1.2` auditd installed, enabled, and active.
  - `3.5.1.3` host firewall active (ufw, or an active nftables ruleset).
  - `1.9` automatic security updates via unattended-upgrades.
  - `6.1.5` `/etc/shadow` permissions ≤ 0640, root-owned.
  - `§2.2` no unnecessary legacy services running (composite deny-list).
  - `§3.3` kernel sysctl network hardening (composite over /proc/sys live values).
  - Shared `_systemd` helper (is-active/is-enabled) for the service-state controls.
  - Test suite grows to 56, still fully OS-independent via `FakeHost`.
- **Remediation engine (Phase 4):** `auditor/remediation.py` — reversible `fix` with a pure
  planning step (`fix(host) -> list[Action]`), a side-effecting `Applier` that backs up every
  file before changing it, and a post-fix re-verification that re-runs the control's own check
  (ADR-0005). Action vocabulary: `WriteFile` / `SetMode` / `SetOwner` / `RunCommand`. New
  `@fixer(check)` registry decorator; the engine/reporters are untouched.
  - CLI: `fix --dry-run` prints the exact plan and changes nothing; `fix` applies with backups
    under `backups/<timestamp>/` (override with `--backup-dir`) and exits non-zero if any fix
    fails to verify.
  - Fixers added for 6 file-based controls (now `implemented+fix`): SSH PermitRootLogin /
    PasswordAuthentication / ciphers (via validated `sshd_config.d` drop-ins + `sshd -t` before
    reload), pwquality minlen (preserving other settings), `/etc/shadow` perms, and sysctl
    (drop-in + `sysctl --system`).
  - Tests: +11 (67 total) — fixer planning, dry-run rendering, the apply→verify loop on a
    mutable fake host, command-failure abort, and `LocalApplier` backup behaviour.
  - Install/enable fixers added for auditd (`4.1.1.2`), host firewall (`3.5.1.3`), and
    unattended-upgrades (`1.9`). The firewall fixer **allows SSH before** enabling default-deny
    so a remote host can't lock itself out. 9 of 10 controls are now `implemented+fix`; only
    `§2.2` stays audit-only (auto-disabling arbitrary services isn't a safe automatic action).
    Tests grow to 71.

### Fixed
- Corrected the SSH root-login control's CIS id from `5.2.8` to **`5.2.7`** to match the
  CIS Ubuntu 22.04 LTS Benchmark **v1.0.0** numbering (verified against public mirrors).

### Changed
- Rewrote `README.md` as a product-facing project showcase (what the tool does, quick start,
  example report, design, roadmap) instead of internal CV-planning notes.

### Notes
- No controls implemented yet. See `docs/CONTROLS.md` for the planned catalogue.
