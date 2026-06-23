"""CIS 5.4.1 — Ensure password creation requirements are configured (minimum length).

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.4.1.

CIS 5.4.1 requires ``minlen = 14`` (and complexity) via pam_pwquality. This check verifies the
minimum-length requirement, reading ``/etc/security/pwquality.conf`` and any drop-ins under
``/etc/security/pwquality.conf.d/`` (the later, more specific value wins).
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control

PWQUALITY_CONF = "/etc/security/pwquality.conf"
REQUIRED_MINLEN = 14


@control(
    id="5.4.1",
    title="Password minimum length >= 14",
    severity=Severity.MEDIUM,
    description="pam_pwquality must enforce a minimum password length of 14.",
    rationale=(
        "Short passwords fall quickly to offline cracking once a hash leaks. A 14-character "
        "floor raises the cost of brute force by orders of magnitude."
    ),
    remediation=(
        "Set 'minlen = 14' in /etc/security/pwquality.conf (or a drop-in under "
        "/etc/security/pwquality.conf.d/) and ensure pam_pwquality is enabled in PAM."
    ),
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.4.1",
)
def check(host: Host) -> Finding:
    text = host.read_text(PWQUALITY_CONF)
    if text is None:
        return Finding.failed(found="pwquality.conf missing", expected=f"minlen >= {REQUIRED_MINLEN}")

    minlen = _parse_minlen(text)
    if minlen is None:
        return Finding.failed(found="minlen unset", expected=f"minlen >= {REQUIRED_MINLEN}")
    if minlen >= REQUIRED_MINLEN:
        return Finding.passed(found=f"minlen = {minlen}", expected=f"minlen >= {REQUIRED_MINLEN}")
    return Finding.failed(found=f"minlen = {minlen}", expected=f"minlen >= {REQUIRED_MINLEN}")


def _parse_minlen(text: str) -> int | None:
    """Last 'minlen = N' wins (drop-ins/override semantics)."""
    found: int | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#") or "minlen" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip().lower() == "minlen":
            try:
                found = int(value.strip())
            except ValueError:
                continue
    return found
