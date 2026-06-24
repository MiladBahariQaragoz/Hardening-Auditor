# Linux Hardening Auditor

A command-line tool that audits a Linux host against the [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
and reports, control by control, where the system deviates from a secure baseline — with a
severity, a clear explanation, and a remediation step for every finding. An optional, reversible
`--fix` mode applies safe hardening automatically.

> **Status:** working. **32 CIS controls** are implemented and mapped to control IDs, 31 with
> safe `--fix` remediation. See the [Roadmap](#roadmap) and [`docs/CONTROLS.md`](docs/CONTROLS.md).

## What it does

- **Audits** SSH configuration, password policy, the audit daemon, the host firewall, file
  permissions on sensitive files, unused services, and kernel `sysctl` hardening — each mapped to
  a real CIS control ID.
- **Scores** the host and groups findings by severity so the most important fixes surface first.
- **Reports** to clean Markdown, HTML, or JSON — a deliverable you can hand to someone, not just
  terminal output.
- **Remediates** safely: `--fix` backs up each file before changing it, runs idempotently, and
  verifies the control passes afterward. `--dry-run` shows exactly what would change first.

## Why

Most security incidents start with a misconfiguration, not an exotic exploit. This tool measures
the gap between a real host and a recognised hardening baseline, and makes closing that gap a
one-command, auditable operation. Every check is tied to the threat it mitigates — see
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

## Quick start

```bash
# Audit the current host (read-only) and print a summary
python -m auditor audit

# Write a Markdown report to reports/
python -m auditor audit --report md

# Preview what remediation would change, without touching anything
python -m auditor fix --dry-run

# Apply safe remediations (backs up every file it changes)
python -m auditor fix
```

> `audit` never modifies the system. Only `fix` makes changes, and only with explicit consent.

## Example report

```
Linux Hardening Audit — lha-audit-vm — 2026-06-24T08:56:21
Score: 53%  (17 / 32 controls passing)

HIGH
  [FAIL] 3.5.1.3  Host firewall active    found "ufw inactive", expected "active firewall"
  [FAIL] 4.1.1.2  auditd enabled and active    found "active=inactive", expected "active + enabled"
  [FAIL] 5.2.7    SSH PermitRootLogin disabled    found "without-password", expected "no"
  [PASS] 6.1.5    /etc/shadow permissions <= 0640
MEDIUM
  [FAIL] 3.3      Kernel network hardening (sysctl)    found "1 of 7 not hardened", expected "all 7 hardened"
  [FAIL] 5.5.1.1  Password expiration <= 365 days    found "PASS_MAX_DAYS=99999", expected "<= 365"
  ...
```

## Before / after (real Ubuntu 22.04 host)

Run end-to-end on a stock **Ubuntu 22.04.5 LTS** Google Compute Engine VM (Python 3.10.12),
auditing live `sshd -T`, `/proc/sys`, `/etc/login.defs`, and real file modes:

| Stage | Score | Passing |
|-------|-------|---------|
| **Before** (default image) | **53 %** | 17 / 32 |
| `fix` (15 controls remediated + verified) | — | — |
| **After** (re-audit) | **100 %** | 32 / 32 |

Every remediated control was re-checked against the live host before being reported as fixed,
each changed file was backed up first, and each SSH change was validated with `sshd -t` before
the daemon was reloaded — so a bad config can never lock you out. This includes the two controls
that both rewrite `/etc/login.defs` (`5.5.1.1` + `5.5.1.2`): both verify simultaneously, the case
that motivated [ADR-0006](docs/DECISIONS.md).

> **What "100 %" means here.** The score is **relative to this tool's own catalogue of 32
> checks** — it reads "all 32 implemented controls pass," not "the host is fully CIS-compliant"
> or "the host is secure." The full CIS Ubuntu 22.04 Benchmark defines *hundreds* of
> recommendations; this project implements a deliberate, well-documented subset (see
> [`docs/CONTROLS.md`](docs/CONTROLS.md)). A 100 % score is a statement about *these* controls,
> not an absolute security guarantee, and should be read alongside the catalogue that defines it.

## Design

The tool is built so that adding a new control never means editing the engine. Each control is a
small, self-registering module under `auditor/checks/`; the engine discovers and runs whatever is
registered and emits a uniform result that the reporters render. The full reasoning behind the
architecture is recorded as Architecture Decision Records in [`docs/DECISIONS.md`](docs/DECISIONS.md).

```
auditor/
├── cli.py            # entrypoint: audit | fix | report
├── engine.py         # discovers + runs checks, collects results
├── registry.py       # control discovery
├── models.py         # Control / CheckResult / Severity dataclasses
├── reporters/        # markdown · html · json
├── remediation.py    # backup → dry-run → fix → verify
└── checks/           # one self-contained module per control
docs/                 # control catalogue, threat model, decision log
```

## Roadmap

- [x] 30+ CIS controls implemented and mapped to control IDs (32 in `docs/CONTROLS.md`)
- [x] Markdown / HTML / JSON reporters (plus a severity-grouped console summary)
- [x] `fix --dry-run` and `fix` remediation with per-file backups and post-fix verification
- [x] Before/after demo on a default Ubuntu 22.04 VM (53 % → 100 %; see above)
- [ ] Comparison of results against [Lynis](https://cisofy.com/lynis/) and OpenSCAP

## Tech

Python 3.10+ (matches Ubuntu 22.04's default), standard library first. Linting with `ruff`,
tests with `pytest`. No external dependencies required to run an audit.

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) ·
  [BSI IT-Grundschutz](https://www.bsi.bund.de/dok/it-grundschutz-kompendium)
- [Lynis](https://cisofy.com/lynis/) · [OpenSCAP](https://www.open-scap.org/)

## License

MIT (see `LICENSE`).
