"""CIS 5.5.1.3 — Ensure password expiration warning days is 7 or more (PASS_WARN_AGE).

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.5.1.3.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._logindefs import get_int, set_action

KEY = "PASS_WARN_AGE"
MINIMUM = 7


@control(
    id="5.5.1.3",
    title="Password expiry warning >= 7 days",
    severity=Severity.LOW,
    description=f"login.defs {KEY} must be {MINIMUM} or more.",
    rationale=(
        "Too little warning before expiry pushes users into rushed, weak password choices or "
        "lockouts at inconvenient times — a usability failure that drives insecure workarounds."
    ),
    remediation=f"Set '{KEY} {MINIMUM}' in /etc/login.defs.",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.5.1.3",
)
def check(host: Host) -> Finding:
    value = get_int(host, KEY)
    if value is None:
        return Finding.failed(found=f"{KEY} unset", expected=f">= {MINIMUM}")
    if value >= MINIMUM:
        return Finding.passed(found=f"{KEY}={value}", expected=f">= {MINIMUM}")
    return Finding.failed(found=f"{KEY}={value}", expected=f">= {MINIMUM}")


@fixer(check)
def fix(host: Host) -> list[Action]:
    return set_action(host, KEY, MINIMUM)
