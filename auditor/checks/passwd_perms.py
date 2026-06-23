"""CIS 6.1.1 — Ensure permissions on /etc/passwd are configured.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 6.1.1 (0644, root:root).
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._fileperms import perm_actions, perm_finding

PATH = "/etc/passwd"


@control(
    id="6.1.1",
    title="/etc/passwd permissions <= 0644",
    severity=Severity.MEDIUM,
    description="/etc/passwd must be root-owned, mode 0644 or stricter.",
    rationale=(
        "/etc/passwd must be world-readable to function, but writable by anyone but root would "
        "let an attacker add accounts or change UIDs to 0. This pins it to root-only writes."
    ),
    remediation="chown root:root /etc/passwd && chmod 0644 /etc/passwd",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 6.1.1",
)
def check(host: Host) -> Finding:
    return perm_finding(host, PATH, max_mode=0o644, owner="root", groups=("root",))


@fixer(check)
def fix(host: Host) -> list[Action]:
    return perm_actions(PATH, 0o644, "root", "root")
