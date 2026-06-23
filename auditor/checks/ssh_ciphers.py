"""CIS 5.2.13 — Ensure only strong Ciphers are used in sshd.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.2.13.

CIS frames this as "weak ciphers must not be offered". We read sshd's effective ``ciphers``
list and fail if any known-weak cipher (CBC modes, arcfour, 3des, etc.) appears. Relying on
the compiled-in default (which is modern on OpenSSH 8.9) still fails the benchmark, which
requires the list to be set explicitly.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control
from ._ssh import effective_config

# Ciphers CIS 22.04 v1.0.0 considers weak — CBC modes and legacy stream ciphers.
WEAK_CIPHERS = frozenset(
    {
        "3des-cbc",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "arcfour",
        "arcfour128",
        "arcfour256",
        "blowfish-cbc",
        "cast128-cbc",
        "rijndael-cbc@lysator.liu.se",
    }
)


@control(
    id="5.2.13",
    title="SSH strong ciphers only",
    severity=Severity.MEDIUM,
    description="sshd must offer only strong ciphers (no CBC/arcfour/3des).",
    rationale=(
        "Weak ciphers (CBC modes, RC4) are vulnerable to known plaintext-recovery and padding "
        "attacks, letting a network attacker weaken or decrypt the session."
    ),
    remediation=(
        "Set an explicit strong 'Ciphers' line in /etc/ssh/sshd_config, e.g. "
        "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
        "aes256-ctr,aes192-ctr,aes128-ctr ; then reload sshd."
    ),
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.2.13",
)
def check(host: Host) -> Finding:
    config, _source = effective_config(host)
    if config is None:
        return Finding.skipped(detail="sshd not present / config unreadable")

    raw = config.get("ciphers")
    if raw is None:
        return Finding.failed(
            found="unset (compiled-in default)",
            expected="explicit strong cipher list",
        )

    offered = [c.strip().lower() for c in raw.split(",") if c.strip()]
    weak = [c for c in offered if c in WEAK_CIPHERS]
    if weak:
        return Finding.failed(found=", ".join(weak), expected="no weak ciphers")
    return Finding.passed(found=raw, expected="no weak ciphers")
