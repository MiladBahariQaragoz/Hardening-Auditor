"""CIS 6.1.3 — Ensure permissions on /etc/group are configured.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 6.1.3 (0644, root:root).
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._fileperms import perm_actions, perm_finding

PATH = "/etc/group"


@control(
    id="6.1.3",
    title="/etc/group permissions <= 0644",
    severity=Severity.MEDIUM,
    description="/etc/group must be root-owned, mode 0644 or stricter.",
    rationale=(
        "A writable /etc/group lets an attacker add themselves to privileged groups (e.g. sudo) "
        "for instant privilege escalation. This restricts writes to root."
    ),
    remediation="chown root:root /etc/group && chmod 0644 /etc/group",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 6.1.3",
)
def check(host: Host) -> Finding:
    return perm_finding(host, PATH, max_mode=0o644, owner="root", groups=("root",))


@fixer(check)
def fix(host: Host) -> list[Action]:
    return perm_actions(PATH, 0o644, "root", "root")
