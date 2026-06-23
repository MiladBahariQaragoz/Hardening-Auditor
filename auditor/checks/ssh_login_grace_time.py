"""CIS 5.2.21 — Ensure SSH LoginGraceTime is set to one minute or less.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.2.21.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._ssh import dropin_actions, require_at_most


@control(
    id="5.2.21",
    title="SSH LoginGraceTime <= 60s",
    severity=Severity.MEDIUM,
    description="sshd must close unauthenticated connections quickly (LoginGraceTime <= 60).",
    rationale=(
        "A long grace period lets an attacker hold many unauthenticated connections open, "
        "exhausting connection slots (a cheap DoS) and widening the brute-force window."
    ),
    remediation="Set 'LoginGraceTime 60' in /etc/ssh/sshd_config.d/ and reload sshd.",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.2.21",
)
def check(host: Host) -> Finding:
    return require_at_most(host, "logingracetime", 60)


@fixer(check)
def fix(host: Host) -> list[Action]:
    return dropin_actions("60-hardening-logingracetime.conf", ["LoginGraceTime 60"])
