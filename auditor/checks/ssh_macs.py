"""CIS 5.2.14 — Ensure only strong MAC algorithms are used in sshd.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.2.14.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._ssh import dropin_actions, require_no_weak

# MD5/SHA1-based and 64-bit MACs CIS treats as weak.
WEAK_MACS = frozenset(
    {
        "hmac-md5",
        "hmac-md5-96",
        "hmac-sha1",
        "hmac-sha1-96",
        "hmac-ripemd160",
        "umac-64@openssh.com",
        "hmac-md5-etm@openssh.com",
        "hmac-md5-96-etm@openssh.com",
        "hmac-sha1-etm@openssh.com",
        "hmac-sha1-96-etm@openssh.com",
        "umac-64-etm@openssh.com",
    }
)
STRONG_MACS = (
    "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
)


@control(
    id="5.2.14",
    title="SSH strong MACs only",
    severity=Severity.MEDIUM,
    description="sshd must offer only strong MAC algorithms (no MD5/SHA1/64-bit).",
    rationale=(
        "Weak MACs (MD5, SHA1, 64-bit UMAC) can be forged or truncated, letting an on-path "
        "attacker tamper with session integrity. Only ETM SHA2/UMAC-128 should be offered."
    ),
    remediation=f"Set 'MACs {STRONG_MACS}' in /etc/ssh/sshd_config.d/ and reload sshd.",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.2.14",
)
def check(host: Host) -> Finding:
    return require_no_weak(host, "macs", WEAK_MACS)


@fixer(check)
def fix(host: Host) -> list[Action]:
    return dropin_actions("60-hardening-macs.conf", [f"MACs {STRONG_MACS}"])
