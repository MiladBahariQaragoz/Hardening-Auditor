"""CIS 5.2.16 — Ensure SSH AllowTcpForwarding is disabled.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.2.16.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._ssh import dropin_actions, require_equals


@control(
    id="5.2.16",
    title="SSH AllowTcpForwarding disabled",
    severity=Severity.MEDIUM,
    description="sshd must not allow TCP port forwarding (AllowTcpForwarding no).",
    rationale=(
        "TCP forwarding turns an SSH session into a tunnel an attacker can use to pivot to "
        "internal services or exfiltrate data past the firewall. Disable it unless required."
    ),
    remediation="Set 'AllowTcpForwarding no' in /etc/ssh/sshd_config.d/ and reload sshd.",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.2.16",
)
def check(host: Host) -> Finding:
    return require_equals(host, "allowtcpforwarding", "no", default_note="default yes")


@fixer(check)
def fix(host: Host) -> list[Action]:
    return dropin_actions("60-hardening-allowtcpforwarding.conf", ["AllowTcpForwarding no"])
