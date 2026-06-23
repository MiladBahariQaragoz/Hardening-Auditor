"""CIS 5.5.1.1 — Ensure password expiration is 365 days or less (PASS_MAX_DAYS).

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.5.1.1.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._logindefs import get_int, set_action

KEY = "PASS_MAX_DAYS"
LIMIT = 365


@control(
    id="5.5.1.1",
    title="Password expiration <= 365 days",
    severity=Severity.MEDIUM,
    description=f"login.defs {KEY} must be {LIMIT} or fewer days.",
    rationale=(
        "Indefinitely-valid passwords mean a credential leaked once stays valid forever. A "
        "maximum age bounds how long a stolen password remains useful."
    ),
    remediation=f"Set '{KEY} {LIMIT}' in /etc/login.defs (and age existing accounts with chage).",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.5.1.1",
)
def check(host: Host) -> Finding:
    value = get_int(host, KEY)
    if value is None:
        return Finding.failed(found=f"{KEY} unset", expected=f"<= {LIMIT}")
    if value <= LIMIT:
        return Finding.passed(found=f"{KEY}={value}", expected=f"<= {LIMIT}")
    return Finding.failed(found=f"{KEY}={value}", expected=f"<= {LIMIT}")


@fixer(check)
def fix(host: Host) -> list[Action]:
    return set_action(host, KEY, LIMIT)
