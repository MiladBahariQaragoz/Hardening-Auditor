"""CIS 1.5.4 — Ensure core dumps are restricted (fs.suid_dumpable = 0).

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 1.5.4. This checks the sysctl
half of the control (setuid programs must not dump core); the full CIS control also sets a
hard limit in limits.conf, noted in the remediation.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._sysctl import expect, set_actions

KEY = "fs.suid_dumpable"


@control(
    id="1.5.4",
    title="Core dumps restricted (suid_dumpable=0)",
    severity=Severity.MEDIUM,
    description=f"{KEY} must be 0 so setuid programs cannot dump core.",
    rationale=(
        "A core dump from a setuid process can spill secrets it held in memory (keys, hashes) "
        "into a file readable by less-privileged users. Disabling suid core dumps closes that leak."
    ),
    remediation=(
        f"Set '{KEY} = 0' in /etc/sysctl.d/ (and '* hard core 0' in /etc/security/limits.d/), "
        "then sysctl --system."
    ),
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 1.5.4",
)
def check(host: Host) -> Finding:
    return expect(host, KEY, "0")


@fixer(check)
def fix(host: Host) -> list[Action]:
    return set_actions(KEY, "0", "60-hardening-coredumps.conf")
