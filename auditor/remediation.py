"""Safe, reversible remediation (ADR-0002, ADR-0005).

The split that makes this safe and testable:

* A control's **fixer** is a pure function ``fix(host) -> list[Action]``. It only *reads* the
  host (via the same read-only ``Host`` checks use) and returns a declarative plan of what
  would change. Planning has no side effects, so dry-run is just "plan, then print".
* An **Applier** performs the side effects: it backs up each file before touching it, then
  executes the actions. ``LocalApplier`` does real I/O; tests use a recording fake.
* After a control's actions are applied, the control's **own check is re-run** to verify the
  fix actually worked — a fix that doesn't make the check pass is reported as failed, not
  assumed good.

The engine never names a control. Adding a fixer is one decorator in the control's module
(``@fixer``); this file does not change.
"""

from __future__ import annotations

import datetime as _dt
import logging
import os
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from .host import Host
from .models import CheckResult, Control, Status
from .registry import check_for, fixer_for, id_sort_key

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------------------------
# Actions — declarative, reversible operations a fixer can ask for.
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class WriteFile:
    """Create or overwrite a file with exact content (optionally setting its mode)."""

    path: str
    content: str
    mode: int | None = None

    @property
    def target(self) -> str | None:
        return self.path

    @property
    def summary(self) -> str:
        extra = f" (mode {self.mode:04o})" if self.mode is not None else ""
        return f"write {self.path}{extra}"


@dataclass(frozen=True)
class SetMode:
    """Change a file's permission bits."""

    path: str
    mode: int

    @property
    def target(self) -> str | None:
        return self.path

    @property
    def summary(self) -> str:
        return f"chmod {self.mode:04o} {self.path}"


@dataclass(frozen=True)
class SetOwner:
    """Change a file's owner and group."""

    path: str
    owner: str
    group: str

    @property
    def target(self) -> str | None:
        return self.path

    @property
    def summary(self) -> str:
        return f"chown {self.owner}:{self.group} {self.path}"


@dataclass(frozen=True)
class RunCommand:
    """Run a command (never via a shell). Not auto-reversible — used for enable/reload/install.

    ``purpose`` documents why, so the dry-run reads clearly.
    """

    argv: tuple[str, ...]
    purpose: str = ""

    @property
    def target(self) -> str | None:
        return None  # nothing to back up

    @property
    def summary(self) -> str:
        why = f"  # {self.purpose}" if self.purpose else ""
        return f"run: {' '.join(self.argv)}{why}"


Action = WriteFile | SetMode | SetOwner | RunCommand


# --------------------------------------------------------------------------------------------
# Plan & outcome records.
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ControlPlan:
    """All the actions that would remediate one failing control."""

    control: Control
    actions: list[Action]


@dataclass
class FixOutcome:
    """What happened when a control's plan was applied."""

    control: Control
    applied: list[Action] = field(default_factory=list)
    verified: Status = Status.ERROR
    backups: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and self.verified is Status.PASS


# --------------------------------------------------------------------------------------------
# Appliers — the side-effecting layer.
# --------------------------------------------------------------------------------------------
@runtime_checkable
class Applier(Protocol):
    def backup(self, path: str) -> str | None:
        """Copy an existing file aside; return the backup path, or None if nothing existed."""
        ...

    def write_file(self, path: str, content: str, mode: int | None) -> None: ...
    def set_mode(self, path: str, mode: int) -> None: ...
    def set_owner(self, path: str, owner: str, group: str) -> None: ...
    def run(self, argv: Sequence[str]) -> tuple[int, str]:
        """Run a command; return (returncode, combined_output)."""
        ...


class LocalApplier:
    """Performs real I/O on the local host, backing up every file before it changes it."""

    def __init__(self, backup_dir: Path) -> None:
        self.backup_dir = backup_dir

    def backup(self, path: str) -> str | None:
        src = Path(path)
        if not src.exists():
            return None
        # Mirror the absolute path under the backup root so collisions can't happen.
        dest = self.backup_dir / src.resolve().relative_to(src.anchor)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        log.info("backed up %s -> %s", path, dest)
        return str(dest)

    def write_file(self, path: str, content: str, mode: int | None) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        if mode is not None:
            os.chmod(p, mode)

    def set_mode(self, path: str, mode: int) -> None:
        os.chmod(path, mode)

    def set_owner(self, path: str, owner: str, group: str) -> None:
        shutil.chown(path, user=owner, group=group)

    def run(self, argv: Sequence[str]) -> tuple[int, str]:
        proc = subprocess.run(  # noqa: S603 — argv list, never shell=True
            list(argv), capture_output=True, text=True, check=False
        )
        return proc.returncode, (proc.stdout + proc.stderr).strip()


def default_backup_dir() -> Path:
    """A timestamped backup directory under ``backups/`` (git-ignored)."""
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path("backups") / stamp


# --------------------------------------------------------------------------------------------
# The engine.
# --------------------------------------------------------------------------------------------
def plan(host: Host, results: Sequence[CheckResult]) -> list[ControlPlan]:
    """Build a remediation plan for every FAILing result that has a registered fixer.

    Read-only: this calls fixers (which only read the host); it changes nothing.
    """
    plans: list[ControlPlan] = []
    for result in sorted(results, key=lambda r: id_sort_key(r.control.id)):
        if result.status is not Status.FAIL:
            continue
        fix = fixer_for(result.control.id)
        if fix is None:
            continue
        actions = list(fix(host))
        if actions:
            plans.append(ControlPlan(control=result.control, actions=actions))
    return plans


def render_dry_run(plans: Sequence[ControlPlan]) -> str:
    """A human-readable preview of exactly what ``fix`` would do — and nothing else."""
    if not plans:
        return "Nothing to remediate: no failing control has an automated fix.\n"
    lines = ["Remediation plan (dry-run — no changes made):", ""]
    for cp in plans:
        lines.append(f"{cp.control.id}  {cp.control.title}")
        for action in cp.actions:
            lines.append(f"    - {action.summary}")
        lines.append("")
    lines.append(f"{len(plans)} control(s) would be remediated. Re-run without --dry-run to apply.")
    return "\n".join(lines) + "\n"


def render_apply(outcomes: Sequence[FixOutcome], backup_dir: Path) -> str:
    """Summarise what was changed and whether each control now passes."""
    if not outcomes:
        return "Nothing to remediate: no failing control has an automated fix.\n"
    lines = [f"Remediation applied (backups in {backup_dir}/):", ""]
    fixed = 0
    for o in outcomes:
        if o.ok:
            fixed += 1
            mark, note = "OK  ", "now passing"
        elif o.error:
            mark, note = "FAIL", o.error
        else:
            mark, note = "WARN", f"applied but still {o.verified.value}"
        lines.append(f"  [{mark}] {o.control.id}  {o.control.title} — {note}")
    lines.append("")
    lines.append(f"{fixed}/{len(outcomes)} control(s) remediated and verified.")
    return "\n".join(lines) + "\n"


def apply(
    host: Host,
    applier: Applier,
    plans: Sequence[ControlPlan],
) -> list[FixOutcome]:
    """Apply each plan with backups, then re-run the control's check to verify."""
    outcomes: list[FixOutcome] = []
    for cp in plans:
        outcome = FixOutcome(control=cp.control)
        try:
            for action in cp.actions:
                _apply_action(applier, action, outcome)
                outcome.applied.append(action)
        except RemediationError as exc:
            outcome.error = str(exc)
            log.error("fix for %s aborted: %s", cp.control.id, exc)
            outcomes.append(outcome)
            continue
        outcome.verified = _verify(host, cp.control.id)
        outcomes.append(outcome)
    return outcomes


class RemediationError(RuntimeError):
    """An action failed; the control's remaining actions are aborted, backups are kept."""


def _apply_action(applier: Applier, action: Action, outcome: FixOutcome) -> None:
    if action.target:
        backup = applier.backup(action.target)
        if backup:
            outcome.backups.append(backup)

    if isinstance(action, WriteFile):
        applier.write_file(action.path, action.content, action.mode)
    elif isinstance(action, SetMode):
        applier.set_mode(action.path, action.mode)
    elif isinstance(action, SetOwner):
        applier.set_owner(action.path, action.owner, action.group)
    elif isinstance(action, RunCommand):
        rc, output = applier.run(action.argv)
        if rc != 0:
            raise RemediationError(f"command failed ({rc}): {' '.join(action.argv)}: {output}")


def _verify(host: Host, control_id: str) -> Status:
    """Re-run the control's check; a fix is only good if the check now passes."""
    registered = check_for(control_id)
    if registered is None:  # pragma: no cover — fixer without a check shouldn't exist
        return Status.ERROR
    try:
        return registered.func(host).status
    except Exception:  # noqa: BLE001
        log.exception("verification of %s raised", control_id)
        return Status.ERROR
