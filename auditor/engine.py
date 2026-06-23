"""The audit engine: discover registered checks, run them against a host, collect results.

The engine is deliberately ignorant of every individual control. It imports the check
package (which triggers self-registration), asks the registry for the checks, runs each one,
and turns the outcome into a uniform ``CheckResult``. A check that raises never crashes the
run — the exception is captured as a ``Status.ERROR`` result so the report is always complete.
"""

from __future__ import annotations

import datetime as _dt
import importlib
import logging
import pkgutil

from . import checks as _checks_pkg
from .host import Host
from .models import AuditReport, CheckResult, Finding, Status
from .registry import RegisteredCheck, all_checks

log = logging.getLogger(__name__)


def discover() -> None:
    """Import every module under ``auditor.checks`` so each self-registers.

    Importing is idempotent — Python caches modules, so calling this repeatedly does not
    double-register. Private modules (leading underscore) are skipped.
    """
    for module in pkgutil.iter_modules(_checks_pkg.__path__):
        if module.name.startswith("_"):
            continue
        importlib.import_module(f"{_checks_pkg.__name__}.{module.name}")


def run_check(check: RegisteredCheck, host: Host) -> CheckResult:
    """Run a single check, converting any exception into a captured ERROR result."""
    try:
        finding = check.func(host)
    except Exception as exc:  # noqa: BLE001 — engine must never crash on a bad check
        log.exception("control %s raised", check.control.id)
        finding = Finding(Status.ERROR, detail=f"{type(exc).__name__}: {exc}")
    log.info("control %s -> %s", check.control.id, finding.status.value)
    return CheckResult(control=check.control, finding=finding)


def run(
    host: Host,
    *,
    checks: list[RegisteredCheck] | None = None,
    timestamp: str | None = None,
) -> AuditReport:
    """Audit ``host`` and return a complete report.

    ``checks`` defaults to every discovered+registered check; pass an explicit list to scope
    a run (used by tests). ``timestamp`` is injectable to keep report output deterministic.
    """
    if checks is None:
        discover()
        checks = all_checks()

    results = [run_check(c, host) for c in checks]
    when = timestamp or _dt.datetime.now().isoformat(timespec="seconds")
    report = AuditReport(host=host.name, timestamp=when, results=results)
    log.info("audit complete: %d/%d controls passing (%d%%)", report.passed, report.total, report.score)
    return report
