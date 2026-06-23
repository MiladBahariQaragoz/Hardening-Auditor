"""CIS 5.2.15 — Ensure only strong Key Exchange algorithms are used in sshd.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.2.15.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._ssh import dropin_actions, require_no_weak

# SHA1-based and small-group key exchanges CIS treats as weak.
WEAK_KEX = frozenset(
    {
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "gss-gex-sha1-",
        "gss-group1-sha1-",
        "gss-group14-sha1-",
    }
)
STRONG_KEX = (
    "curve25519-sha256,curve25519-sha256@libssh.org,"
    "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
    "diffie-hellman-group-exchange-sha256"
)


@control(
    id="5.2.15",
    title="SSH strong key exchange only",
    severity=Severity.MEDIUM,
    description="sshd must offer only strong KexAlgorithms (no SHA1/small-group).",
    rationale=(
        "SHA1-based and 1024-bit-group key exchanges are within reach of well-resourced "
        "attackers, threatening the confidentiality of the whole session key. Only "
        "curve25519/SHA2 exchanges should be offered."
    ),
    remediation=f"Set 'KexAlgorithms {STRONG_KEX}' in /etc/ssh/sshd_config.d/ and reload sshd.",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.2.15",
)
def check(host: Host) -> Finding:
    return require_no_weak(host, "kexalgorithms", WEAK_KEX)


@fixer(check)
def fix(host: Host) -> list[Action]:
    return dropin_actions("60-hardening-kex.conf", [f"KexAlgorithms {STRONG_KEX}"])
