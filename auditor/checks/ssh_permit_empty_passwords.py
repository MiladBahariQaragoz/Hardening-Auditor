"""CIS 5.2.9 — Ensure SSH PermitEmptyPasswords is disabled.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.2.9.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._ssh import dropin_actions, require_equals


@control(
    id="5.2.9",
    title="SSH PermitEmptyPasswords disabled",
    severity=Severity.HIGH,
    description="sshd must reject accounts with empty passwords (PermitEmptyPasswords no).",
    rationale=(
        "An account with an empty password is a remote login with no secret at all — an open "
        "door. This guarantees sshd never honours one even if such an account exists."
    ),
    remediation="Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config.d/ and reload sshd.",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.2.9",
)
def check(host: Host) -> Finding:
    return require_equals(host, "permitemptypasswords", "no", default_note="default no")


@fixer(check)
def fix(host: Host) -> list[Action]:
    return dropin_actions("60-hardening-permitemptypasswords.conf", ["PermitEmptyPasswords no"])
