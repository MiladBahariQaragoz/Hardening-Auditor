"""CIS 5.2.1 — Ensure permissions on /etc/ssh/sshd_config are configured.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.2.1 (0600, root:root).
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._fileperms import perm_actions, perm_finding

PATH = "/etc/ssh/sshd_config"


@control(
    id="5.2.1",
    title="sshd_config permissions <= 0600",
    severity=Severity.MEDIUM,
    description="/etc/ssh/sshd_config must be root-owned, mode 0600 or stricter.",
    rationale=(
        "A writable sshd_config lets a low-priv user weaken SSH (e.g. re-enable root login); a "
        "readable one leaks the server's exact auth posture to an attacker scoping the host."
    ),
    remediation="chown root:root /etc/ssh/sshd_config && chmod 0600 /etc/ssh/sshd_config",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.2.1",
)
def check(host: Host) -> Finding:
    return perm_finding(host, PATH, max_mode=0o600, owner="root", groups=("root",))


@fixer(check)
def fix(host: Host) -> list[Action]:
    return perm_actions(PATH, 0o600, "root", "root")
