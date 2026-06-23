"""CIS §3.3 — Ensure kernel network parameters are hardened (sysctl).

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, section 3.3 ("Network Parameters
(Host)"). Composite check over the core 3.3.x parameters. Values are read from ``/proc/sys``
(the live kernel state), so the result reflects what the kernel is actually enforcing, not
just what a config file claims.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control

# (CIS sub-id, /proc/sys path, required value). Paths use the /proc/sys layout so we can read
# the live value directly via Host.read_text.
PARAMETERS = (
    ("3.3.1", "/proc/sys/net/ipv4/ip_forward", "0"),
    ("3.3.2", "/proc/sys/net/ipv4/conf/all/send_redirects", "0"),
    ("3.3.3", "/proc/sys/net/ipv4/conf/all/accept_source_route", "0"),
    ("3.3.4", "/proc/sys/net/ipv4/conf/all/accept_redirects", "0"),
    ("3.3.5", "/proc/sys/net/ipv4/conf/all/secure_redirects", "0"),
    ("3.3.9", "/proc/sys/net/ipv4/conf/all/rp_filter", "1"),
    ("3.3.10", "/proc/sys/net/ipv4/tcp_syncookies", "1"),
)


@control(
    id="3.3",
    title="Kernel network hardening (sysctl)",
    severity=Severity.MEDIUM,
    description="Core net.ipv4 sysctl parameters must be set to their hardened values.",
    rationale=(
        "Default kernel network settings allow routing, redirects, and source-routed packets "
        "an endpoint never needs — primitives an attacker uses for spoofing, MITM redirection, "
        "and traffic interception. Hardening them removes those primitives."
    ),
    remediation=(
        "Set the hardened values in /etc/sysctl.d/ (e.g. net.ipv4.ip_forward=0, "
        "net.ipv4.conf.all.accept_redirects=0, net.ipv4.tcp_syncookies=1) and apply with "
        "sysctl --system."
    ),
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — §3.3 (network parameters)",
)
def check(host: Host) -> Finding:
    misconfigured: list[str] = []
    readable = 0
    for cid, path, want in PARAMETERS:
        raw = host.read_text(path)
        if raw is None:
            continue  # parameter not present on this kernel; don't penalise
        readable += 1
        if raw.strip() != want:
            misconfigured.append(f"{cid}:{path.rsplit('/', 1)[-1]}={raw.strip()}≠{want}")

    expected = f"all {len(PARAMETERS)} parameters hardened"
    if readable == 0:
        return Finding.skipped(detail="/proc/sys network parameters unreadable")
    if misconfigured:
        return Finding.failed(
            found=f"{len(misconfigured)} of {readable} not hardened: " + "; ".join(misconfigured),
            expected=expected,
        )
    return Finding.passed(found=f"{readable}/{readable} hardened", expected=expected)
