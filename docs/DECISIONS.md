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

## ADR-0004 — Checks read the system through an injected `Host`, never directly
- **Date:** 2026-06-23
- **Status:** Accepted
- **Context:** Checks need to read config files, file permissions, and command output from a
  Linux host. If each check calls `open()`/`subprocess` directly, the suite can only run on a
  real Linux box, the tool can only audit *localhost*, and every system access is an untestable
  side effect. Development happens on a Windows machine, so this would block testing entirely.
- **Decision:** Introduce a narrow `Host` protocol (`read_text`, `stat`, `run`) in
  `auditor/host.py`. Checks receive a `Host` and ask it for facts. `LocalHost` is the only
  OS-touching implementation (runs *on* the target); `FakeHost` (in `tests/`) serves canned
  files/metadata/command output. Unix-only imports (`pwd`/`grp`) are deferred into methods so
  the module imports cleanly on Windows.
- **Consequences:** The full test suite runs on any OS with no Linux required; a future
  `RemoteHost` (audit over SSH) drops in without touching a single check; every system access
  flows through one loggable surface. Cost: one extra indirection and a small fake to maintain.

## ADR-0005 — Remediation = pure planning + a separate applier + re-verification
- **Date:** 2026-06-23
- **Status:** Accepted
- **Context:** `fix` must change a real host's security configuration safely (ADR-0002). The
  danger is an opaque, irreversible change. We also want remediation to stay testable on the
  Windows dev box and to never grow the engine per control (ADR-0001).
- **Decision:** Split remediation into three parts. (1) A control's **fixer** is a pure
  function `fix(host) -> list[Action]`; it only *reads* the host and returns a declarative
  plan, so `--dry-run` is "plan, then print" with zero side effects. (2) An **Applier**
  performs the side effects, **backing up every file before it changes it**; `LocalApplier`
  does real I/O, tests use a recording fake. (3) After a control's actions are applied, the
  control's **own check is re-run to verify** — a fix that doesn't make the check pass is
  reported as failed, not assumed. Actions are a small reversible vocabulary (`WriteFile`,
  `SetMode`, `SetOwner`, `RunCommand`); SSH/sysctl changes go in drop-in files, and SSH fixes
  run `sshd -t` before reloading so a bad config can never lock out access. Fixers register via
  one `@fixer(check)` decorator in the control's own module.
- **Consequences:** Dry-run is trustworthy by construction; the plan/apply split makes both
  halves unit-testable; the engine never changes when a fixer is added. `RunCommand` is not
  auto-reversible (used for reload/enable/install) — accepted, and offset by the kept backups
  and the verify step. Verifying state changed by the kernel (e.g. `sysctl --system` updating
  `/proc/sys`) is covered on a live host, not by the in-memory fake.

## ADR-0006 — Apply re-derives each fixer against the live host, not the up-front plan
- **Date:** 2026-06-24
- **Status:** Accepted
- **Context:** Under ADR-0005, `fix` plans up front and `apply` executes that plan. Several
  controls legitimately edit the *same* file: e.g. `5.5.1.1` (`PASS_MAX_DAYS`) and `5.5.1.2`
  (`PASS_MIN_DAYS`) both rewrite `/etc/login.defs` via a whole-file `WriteFile`. Because each
  `WriteFile` captured the file's content **at plan time** (before any fix ran), applying them
  in sequence meant the second write — built from the original file — silently clobbered the
  first fixer's change. The first control verified, then got reverted; only the last writer of
  a shared file survived. This surfaced during the GCP demo run.
- **Decision:** `apply` re-derives each control's actions by calling its fixer **again at apply
  time**, against the live host (which already reflects earlier fixers' writes), rather than
  replaying the stale `ControlPlan.actions`. Fixers are pure, read-only, and cheap (ADR-0005),
  so re-running them is safe and side-effect-free. The up-front plan is still what `--dry-run`
  renders — the read-only preview is unchanged. `LocalApplier.backup` now also skips re-copying
  a file already backed up earlier in the same run, so the kept backup is the true pre-run
  original even when two controls touch one file.
- **Consequences:** Order-independent correctness for controls sharing a file; no per-control
  special-casing in the engine (ADR-0001 preserved). The trade-off: the actions actually
  applied are re-computed, so in principle they could differ from the dry-run preview if the
  host changed between plan and apply — acceptable, since re-deriving against current truth is
  *more* correct, and the verify step (ADR-0005) still gates success. Tests cover both the
  shared-file case (`5.5.1.1` + `5.5.1.2` both verify) and the command-failure abort path.
