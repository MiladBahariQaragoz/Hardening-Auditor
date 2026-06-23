"""CIS §2.2 — Ensure unnecessary / legacy network services are not running.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, section 2.2 ("Special Purpose
Services"). This is a composite check over a deny-list of high-risk legacy daemons that CIS
recommends not be present (each is its own 2.2.x sub-control). The check fails if any of them
is active, naming the offenders.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control
from ._systemd import active_state

# Legacy/cleartext or rarely-needed listening services CIS §2.2 flags. Unit names as used by
# systemd on Ubuntu; absent units simply report no state and are treated as "not running".
DENY_LIST = (
    "telnet.socket",
    "rsh.socket",
    "rlogin.socket",
    "rexec.socket",
    "tftp.socket",
    "vsftpd",
    "avahi-daemon",
    "cups",
    "isc-dhcp-server",
    "slapd",
    "nfs-server",
    "bind9",
    "dovecot",
    "smbd",
    "snmpd",
    "squid",
    "rpcbind",
)


@control(
    id="2.2",
    title="No unnecessary legacy services running",
    severity=Severity.MEDIUM,
    description="High-risk legacy services (telnet, rsh, tftp, etc.) must not be active.",
    rationale=(
        "Every listening service is attack surface; cleartext legacy daemons (telnet, rsh, "
        "tftp) also leak credentials on the wire. Removing what you don't use removes the "
        "vulnerabilities you'd otherwise have to track in it."
    ),
    remediation=(
        "For each offender: systemctl --now disable <service> (or apt purge the package). "
        "Keep only services this host is meant to expose."
    ),
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — §2.2 (special purpose services)",
)
def check(host: Host) -> Finding:
    running = [unit for unit in DENY_LIST if active_state(host, unit) == "active"]
    expected = "none of the deny-listed services active"
    if running:
        return Finding.failed(found=", ".join(running), expected=expected)
    return Finding.passed(found="none active", expected=expected)
