"""CIS 1.3.1 — Ensure AppArmor is installed and enabled.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, §1.3 (Mandatory Access Control).
Checks the live kernel flag at /sys/module/apparmor/parameters/enabled, which is 'Y' only when
AppArmor is installed and active. Audit-only: enabling AppArmor requires bootloader changes and
a reboot, which is not a safe unattended `fix`.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control

APPARMOR_FLAG = "/sys/module/apparmor/parameters/enabled"


@control(
    id="1.3.1",
    title="AppArmor enabled",
    severity=Severity.MEDIUM,
    description="The AppArmor LSM must be installed and active in the kernel.",
    rationale=(
        "AppArmor confines programs to the files and capabilities they legitimately need, so a "
        "compromised service can't roam the whole system. Without it, a single exploited daemon "
        "has the run of everything its UID can touch."
    ),
    remediation=(
        "apt install apparmor apparmor-utils; ensure 'apparmor=1 security=apparmor' kernel "
        "params are set (update-grub) and reboot."
    ),
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — §1.3 (1.3.1)",
)
def check(host: Host) -> Finding:
    flag = host.read_text(APPARMOR_FLAG)
    if flag is None:
        return Finding.failed(found="apparmor module not loaded", expected="enabled (Y)")
    if flag.strip() == "Y":
        return Finding.passed(found="Y", expected="Y")
    return Finding.failed(found=flag.strip(), expected="Y")
