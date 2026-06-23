"""CIS 5.2.6 — Ensure SSH PAM is enabled (UsePAM yes).

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.2.6.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._ssh import dropin_actions, require_equals


@control(
    id="5.2.6",
    title="SSH UsePAM enabled",
    severity=Severity.MEDIUM,
    description="sshd must use PAM so account/session policy is enforced (UsePAM yes).",
    rationale=(
        "PAM is where account expiry, access limits, and session controls live. With UsePAM "
        "off, sshd bypasses those policies entirely."
    ),
    remediation="Set 'UsePAM yes' in /etc/ssh/sshd_config.d/ and reload sshd.",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.2.6",
)
def check(host: Host) -> Finding:
    return require_equals(host, "usepam", "yes")


@fixer(check)
def fix(host: Host) -> list[Action]:
    return dropin_actions("60-hardening-usepam.conf", ["UsePAM yes"])
