"""CIS 1.5.1 — Ensure address space layout randomization (ASLR) is enabled.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 1.5.1
(kernel.randomize_va_space = 2).
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._sysctl import expect, set_actions

KEY = "kernel.randomize_va_space"


@control(
    id="1.5.1",
    title="ASLR enabled",
    severity=Severity.MEDIUM,
    description=f"{KEY} must be 2 (full address-space randomization).",
    rationale=(
        "ASLR randomizes memory layout so an attacker can't rely on fixed addresses for "
        "memory-corruption exploits. Disabling it makes such exploits dramatically easier."
    ),
    remediation=f"Set '{KEY} = 2' in /etc/sysctl.d/ and apply with sysctl --system.",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 1.5.1",
)
def check(host: Host) -> Finding:
    return expect(host, KEY, "2")


@fixer(check)
def fix(host: Host) -> list[Action]:
    return set_actions(KEY, "2", "60-hardening-aslr.conf")
