"""CIS 5.2.5 — Ensure SSH LogLevel is appropriate (INFO or VERBOSE).

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.2.5.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._ssh import dropin_actions, require_in


@control(
    id="5.2.5",
    title="SSH LogLevel INFO/VERBOSE",
    severity=Severity.MEDIUM,
    description="sshd LogLevel must be INFO or VERBOSE so logins are recorded.",
    rationale=(
        "Below INFO, sshd stops recording the logins and key fingerprints incident responders "
        "need to reconstruct who connected. VERBOSE additionally logs the key used."
    ),
    remediation="Set 'LogLevel VERBOSE' in /etc/ssh/sshd_config.d/ and reload sshd.",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.2.5",
)
def check(host: Host) -> Finding:
    return require_in(host, "loglevel", ("INFO", "VERBOSE"))


@fixer(check)
def fix(host: Host) -> list[Action]:
    return dropin_actions("60-hardening-loglevel.conf", ["LogLevel VERBOSE"])
