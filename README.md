# Linux Hardening Auditor

A command-line tool that audits a Linux host against the [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
and reports, control by control, where the system deviates from a secure baseline — with a
severity, a clear explanation, and a remediation step for every finding. An optional, reversible
`--fix` mode applies safe hardening automatically.

> **Status:** early development. The architecture and control catalogue are in place; checks are
> being implemented incrementally. See the [Roadmap](#roadmap) and [`docs/CONTROLS.md`](docs/CONTROLS.md).

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
Linux Hardening Audit — ubuntu-host — 2026-06-23
Score: 41%  (14 / 34 controls passing)

HIGH
  [FAIL] 5.2  SSH PermitRootLogin    found "yes", expected "no"
  [FAIL] 6.1  /etc/shadow perms      found 0644, expected 0640
  [PASS] 4.1  auditd enabled
MEDIUM
  [FAIL] 3.3  sysctl net.ipv4.*      3 of 7 parameters not hardened
  ...
```

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

- [ ] 30+ CIS controls implemented and mapped to control IDs (catalogue seeded in `docs/CONTROLS.md`)
- [ ] Markdown / HTML / JSON reporters
- [ ] `--dry-run` and `--fix` remediation with backups
- [ ] Before/after demo on a default vs. hardened VM, with screenshots
- [ ] Comparison of results against [Lynis](https://cisofy.com/lynis/) and OpenSCAP

## Tech

Python 3.11+, standard library first. Linting with `ruff`, tests with `pytest`. No external
dependencies required to run an audit.

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) ·
  [BSI IT-Grundschutz](https://www.bsi.bund.de/dok/it-grundschutz-kompendium)
- [Lynis](https://cisofy.com/lynis/) · [OpenSCAP](https://www.open-scap.org/)

## License

MIT (see `LICENSE`).
