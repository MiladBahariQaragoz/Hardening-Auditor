"""CIS 6.1.7 — Ensure permissions on /etc/gshadow are configured.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 6.1.7 (0640, root:shadow).
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._fileperms import perm_actions, perm_finding

PATH = "/etc/gshadow"


@control(
    id="6.1.7",
    title="/etc/gshadow permissions <= 0640",
    severity=Severity.HIGH,
    description="/etc/gshadow must be root-owned, group shadow, mode 0640 or stricter.",
    rationale=(
        "/etc/gshadow holds group password hashes; world/group-readable access hands an attacker "
        "crackable material for privileged groups, mirroring the /etc/shadow risk."
    ),
    remediation="chown root:shadow /etc/gshadow && chmod 0640 /etc/gshadow",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 6.1.7",
)
def check(host: Host) -> Finding:
    return perm_finding(host, PATH, max_mode=0o640, owner="root", groups=("shadow", "root"))


@fixer(check)
def fix(host: Host) -> list[Action]:
    return perm_actions(PATH, 0o640, "root", "shadow")
