"""CIS 5.1.2 — Ensure permissions on /etc/crontab are configured.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.1.2 (0600, root:root).
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._fileperms import perm_actions, perm_finding

PATH = "/etc/crontab"


@control(
    id="5.1.2",
    title="/etc/crontab permissions <= 0600",
    severity=Severity.MEDIUM,
    description="/etc/crontab must be root-owned, mode 0600 or stricter.",
    rationale=(
        "Cron jobs in /etc/crontab run as root. A writable crontab is a direct path to root code "
        "execution; a readable one reveals scheduled tasks an attacker can target or time around."
    ),
    remediation="chown root:root /etc/crontab && chmod 0600 /etc/crontab",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.1.2",
)
def check(host: Host) -> Finding:
    return perm_finding(host, PATH, max_mode=0o600, owner="root", groups=("root",))


@fixer(check)
def fix(host: Host) -> list[Action]:
    return perm_actions(PATH, 0o600, "root", "root")
