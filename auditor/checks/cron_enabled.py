"""CIS 5.1.1 — Ensure cron daemon is enabled and running.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.1.1.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action, RunCommand
from ._systemd import active_state, enabled_state


@control(
    id="5.1.1",
    title="cron daemon enabled and active",
    severity=Severity.LOW,
    description="The cron service must be enabled and running.",
    rationale=(
        "Many security tasks (log rotation, AIDE/integrity scans, automatic updates) run from "
        "cron. If cron isn't running, those protections silently stop happening."
    ),
    remediation="systemctl --now enable cron",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.1.1",
)
def check(host: Host) -> Finding:
    active = active_state(host, "cron")
    enabled = enabled_state(host, "cron")
    if not active and not enabled:
        return Finding.failed(found="not installed / unknown unit", expected="active + enabled")
    if active == "active" and enabled == "enabled":
        return Finding.passed(found="active, enabled", expected="active + enabled")
    return Finding.failed(
        found=f"active={active or 'unknown'}, enabled={enabled or 'unknown'}",
        expected="active + enabled",
    )


@fixer(check)
def fix(host: Host) -> list[Action]:
    return [RunCommand(("systemctl", "enable", "--now", "cron"), "enable and start cron")]
