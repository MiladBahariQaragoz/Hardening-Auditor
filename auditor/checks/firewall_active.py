"""CIS 3.5.1.3 — Ensure a host firewall is enabled and active (ufw, or nftables).

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 3.5.1.3 (ufw service enabled).
CIS picks ufw as the default Ubuntu firewall; this check accepts an active nftables ruleset as
an equivalent host firewall so the control is meaningful on hosts that chose nftables instead.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control
from ._systemd import is_active


@control(
    id="3.5.1.3",
    title="Host firewall active",
    severity=Severity.HIGH,
    description="A default-deny host firewall (ufw or nftables) must be active.",
    rationale=(
        "Default-deny inbound shrinks the attack surface to only the services you intend to "
        "expose, neutralising forgotten or accidentally-listening daemons."
    ),
    remediation="ufw default deny incoming && ufw allow OpenSSH && ufw --force enable",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 3.5.1.3",
)
def check(host: Host) -> Finding:
    # Primary: ufw reports its own status (more reliable than the unit alone).
    ufw = host.run(["ufw", "status"])
    if ufw.ok and "status: active" in ufw.stdout.lower():
        return Finding.passed(found="ufw active", expected="active firewall")

    # Accept an active nftables service as an equivalent host firewall.
    if is_active(host, "nftables"):
        return Finding.passed(found="nftables active", expected="active firewall")

    if ufw.ok and "status: inactive" in ufw.stdout.lower():
        return Finding.failed(found="ufw inactive", expected="active firewall")
    return Finding.failed(found="no active host firewall", expected="active firewall")
