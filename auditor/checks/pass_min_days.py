"""CIS 5.5.1.2 — Ensure minimum days between password changes is configured (PASS_MIN_DAYS).

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.5.1.2.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._logindefs import get_int, set_action

KEY = "PASS_MIN_DAYS"
MINIMUM = 1


@control(
    id="5.5.1.2",
    title="Minimum days between password changes >= 1",
    severity=Severity.MEDIUM,
    description=f"login.defs {KEY} must be {MINIMUM} or more.",
    rationale=(
        "Without a minimum age, a user forced to change a password can immediately cycle back "
        "to the old one, defeating expiry and history controls."
    ),
    remediation=f"Set '{KEY} {MINIMUM}' in /etc/login.defs.",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.5.1.2",
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
