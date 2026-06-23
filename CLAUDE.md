# Linux Hardening Auditor — project guide for Claude

A Python tool that audits a Linux host against the **CIS Benchmark** (and, where relevant,
**BSI IT-Grundschutz**), reports pass/fail per control with severity + remediation, and can
optionally **remediate** safely (`--dry-run`, `--fix`, with backups). Full intent in `README.md`.

This is a CV / portfolio project for a junior security role. The code must *look* like the work
of someone who understands secure systems — clean, mapped to real control IDs, and auditable.

## Three non-negotiable principles
Every change is judged against these. If a change makes one worse, stop and reconsider.

1. **Scalable** — adding control #41 must not mean editing 6 files. Controls are *data-driven
   plugins*: one self-contained check module + one registry entry. The engine, reporter, and
   remediator never grow when you add a control.
2. **Traceable** — every control maps to a CIS control ID; every run is reproducible; every
   non-trivial decision is written down. A reader can go from a CV bullet → report line →
   control ID → the exact check code → the rationale, with no missing link.
3. **Debuggable** — structured logging at every check, deterministic output, dry-run by default,
   small single-purpose functions, and clear failure messages (what was expected vs. found).

## Non-negotiable markdown files — keep these CURRENT, every task
Updating these is part of "done", not optional cleanup. A task is not finished until the
relevant file below is updated **in the same commit** as the code.

| File | What it records | When to update |
|------|-----------------|----------------|
| `README.md` | What the tool is, how to run it, before/after score | When behaviour or usage changes |
| `CHANGELOG.md` | Human-readable history (Keep a Changelog format) | **Every** commit that changes behaviour |
| `docs/DECISIONS.md` | Architecture Decision Records — why, not just what | When a design choice is made or reversed |
| `docs/CONTROLS.md` | The control catalogue: CIS ID → check → severity → status | When a control is added/changed/removed |
| `docs/THREAT-MODEL.md` | Why each control matters (rationale for recruiters) | When a control's rationale is established |

If you add code without touching the file that should describe it, you are not done.

## Git workflow — IMPORTANT
**Every discrete unit of work gets its own commit + push.** Keep commits small and
single-purpose so history stays debuggable.
1. `git add` the relevant files (code **and** its markdown),
2. `git commit` with a conventional message (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`),
3. `git push` to `origin main`.

Never batch unrelated changes. Never commit secrets (`.env`, keys are git-ignored).
End commit messages with the `Co-Authored-By: Claude ...` trailer.

## Intended architecture (scalable by design)
```
linux-hardening-auditor/
├── auditor/
│   ├── __init__.py
│   ├── cli.py            # argparse entrypoint: audit | fix | report
│   ├── engine.py         # discovers + runs checks, collects Results — never edited per-control
│   ├── models.py         # Control, CheckResult, Severity, Status dataclasses
│   ├── registry.py       # control discovery (the only place that knows checks exist)
│   ├── reporters/        # markdown.py, html.py, json.py — pluggable output
│   ├── remediation.py    # safe apply: backup → dry-run diff → fix → verify
│   └── checks/           # ONE module per control, self-registering
│       ├── ssh_permit_root_login.py
│       ├── ssh_password_auth.py
│       └── ...
├── tests/                # one test per check + engine/reporter tests
├── reports/              # generated artifacts (git-ignored; .gitkeep tracked)
├── docs/                 # the maintained markdown (see table above)
└── README.md / CHANGELOG.md / CLAUDE.md
```

### Adding a control (the scalable path)
1. Create `auditor/checks/<cis_id>_<slug>.py` implementing the check contract.
2. It self-registers (decorator or registry entry) — engine/reporter untouched.
3. Add a row to `docs/CONTROLS.md` and a rationale to `docs/THREAT-MODEL.md`.
4. Add a test in `tests/`.
5. Add a `CHANGELOG.md` line. Commit + push.

## Stack & conventions
- **Python 3.11+**, standard library first. Prefer `dataclasses`, `pathlib`, `subprocess`
  (never `shell=True`), `logging` (structured, never bare `print` for diagnostics).
- Read-only by default. Mutating actions require `--fix` and always back up first.
- Deterministic output: stable ordering by control ID so report diffs are meaningful.
- Lint/format: `ruff`. Tests: `pytest`. Type hints everywhere; check with `mypy` if configured.

## How to run (once implemented)
```
python -m auditor audit                 # read-only audit, prints summary
python -m auditor audit --report md      # write Markdown report to reports/
python -m auditor fix --dry-run          # show what --fix would change
python -m auditor fix                    # apply safe remediations (with backups)
```

## Definition of done (mirrors README)
A control/feature is done when: code works, a test covers it, output is deterministic,
**and** every applicable markdown file in the table above is updated in the same commit.
