"""CIS 5.2.7 — Ensure SSH root login is disabled (``PermitRootLogin no``).

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.2.7.
Rationale lives in docs/THREAT-MODEL.md; this docstring records the exact benchmark mapping.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._ssh import dropin_actions, effective_config


@control(
    id="5.2.7",
    title="SSH PermitRootLogin disabled",
    severity=Severity.HIGH,
    description="sshd must refuse direct root login (PermitRootLogin no).",
    rationale=(
        "Direct root login lets an attacker brute-force the single most valuable account and "
        "removes the audit gap between who logged in and who became root."
    ),
    remediation=(
        "Set 'PermitRootLogin no' in /etc/ssh/sshd_config (or a drop-in under "
        "/etc/ssh/sshd_config.d/), then reload sshd: systemctl reload ssh."
    ),
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.2.7",
)
def check(host: Host) -> Finding:
    config, _source = effective_config(host)
    if config is None:
        return Finding.skipped(detail="sshd not present / config unreadable")

    value = config.get("permitrootlogin")
    if value is None:
        # Absent from the file → sshd's built-in default 'prohibit-password' applies,
        # which still permits key-based root login and fails the "disabled" requirement.
        return Finding.failed(found="unset (default: prohibit-password)", expected="no")
    if value.lower() == "no":
        return Finding.passed(found=value, expected="no")
    return Finding.failed(found=value, expected="no")


@fixer(check)
def fix(host: Host) -> list[Action]:
    return dropin_actions("60-hardening-permitrootlogin.conf", ["PermitRootLogin no"])
