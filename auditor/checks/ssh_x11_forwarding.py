"""CIS 5.2.12 — Ensure SSH X11 forwarding is disabled.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.2.12.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._ssh import dropin_actions, require_equals


@control(
    id="5.2.12",
    title="SSH X11Forwarding disabled",
    severity=Severity.MEDIUM,
    description="sshd must not tunnel X11 (X11Forwarding no).",
    rationale=(
        "X11 forwarding exposes the client's X server to the server side; a compromised server "
        "can sniff keystrokes or inject events into the user's session. Disable it unless needed."
    ),
    remediation="Set 'X11Forwarding no' in /etc/ssh/sshd_config.d/ and reload sshd.",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.2.12",
)
def check(host: Host) -> Finding:
    return require_equals(host, "x11forwarding", "no", default_note="default no")


@fixer(check)
def fix(host: Host) -> list[Action]:
    return dropin_actions("60-hardening-x11forwarding.conf", ["X11Forwarding no"])
