"""CIS 4.1.1.2 — Ensure auditd service is enabled and active.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 4.1.1.2 (which also implies
4.1.1.1, "auditd is installed" — an unknown/inactive unit means the package isn't doing its
job either way).
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control
from ._systemd import active_state, enabled_state


@control(
    id="4.1.1.2",
    title="auditd enabled and active",
    severity=Severity.HIGH,
    description="The audit daemon must be installed, enabled, and running.",
    rationale=(
        "Without a kernel audit trail a post-compromise attacker operates blind to defenders — "
        "no record of privilege escalation, file tampering, or persistence. auditd is the "
        "detection backbone the other controls assume exists."
    ),
    remediation="apt install auditd audispd-plugins && systemctl --now enable auditd",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 4.1.1.2",
)
def check(host: Host) -> Finding:
    active = active_state(host, "auditd")
    enabled = enabled_state(host, "auditd")

    if not active and not enabled:
        # Empty states usually mean the unit is unknown — auditd isn't installed at all.
        return Finding.failed(found="not installed / unknown unit", expected="active + enabled")
    if active == "active" and enabled == "enabled":
        return Finding.passed(found="active, enabled", expected="active + enabled")
    return Finding.failed(
        found=f"active={active or 'unknown'}, enabled={enabled or 'unknown'}",
        expected="active + enabled",
    )
