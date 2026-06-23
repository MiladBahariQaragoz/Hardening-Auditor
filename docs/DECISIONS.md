# Architecture Decision Records (ADR)

Each decision is numbered, dated, and immutable once accepted. To reverse a decision,
add a new ADR that supersedes the old one (don't edit history) — that is what keeps the
"why" **traceable**. Status: `Proposed` | `Accepted` | `Superseded by ADR-NNN`.

---

## ADR-0001 — Controls are data-driven, self-registering plugins
- **Date:** 2026-06-23
- **Status:** Accepted
- **Context:** A CV-grade auditor needs 30–50 controls and will keep growing. If adding a
  control requires editing the engine, reporter, and a big `if/elif` block, the project stops
  being scalable and every addition risks regressions.
- **Decision:** Each control lives in its own module under `auditor/checks/` and registers
  itself with a central registry. The engine discovers and runs whatever is registered; it
  never names individual controls. Reporters consume a uniform `CheckResult`.
- **Consequences:** Adding control #N touches only its own file + the maintained docs + a test.
  Engine/reporter complexity stays constant. Slight indirection cost (registry lookup) accepted.

## ADR-0002 — Read-only by default; remediation is opt-in and reversible
- **Date:** 2026-06-23
- **Status:** Accepted
- **Context:** The tool inspects and can change a host's security configuration. An accidental
  destructive change on a real machine is the worst failure mode.
- **Decision:** `audit` never mutates. Remediation requires explicit `fix`, defaults to
  `--dry-run` semantics where practical, backs up every file before changing it, and verifies
  the control passes afterward. Each fix is idempotent.
- **Consequences:** Safer demo and real use; more code per control (backup/verify), accepted as
  the cost of being **debuggable** and trustworthy.

## ADR-0003 — Every control maps to a real benchmark control ID
- **Date:** 2026-06-23
- **Status:** Accepted
- **Context:** Recruiters and auditors trust mapped controls, not ad-hoc checks.
- **Decision:** Every check carries a CIS Benchmark control ID (and BSI Grundschutz ref where
  it adds value). The ID flows from `docs/CONTROLS.md` → check module → report line, unbroken.
- **Consequences:** Slightly more upfront research per control; full **traceability** from CV
  bullet to source code.
