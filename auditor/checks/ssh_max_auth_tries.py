"""CIS 5.2.18 — Ensure SSH MaxAuthTries is set to 4 or less.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.2.18.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._ssh import dropin_actions, require_at_most


@control(
    id="5.2.18",
    title="SSH MaxAuthTries <= 4",
    severity=Severity.MEDIUM,
    description="sshd must cap authentication attempts per connection (MaxAuthTries <= 4).",
    rationale=(
        "A low cap on auth attempts per connection slows online password/key guessing and makes "
        "brute-force bursts noisy enough to detect."
    ),
    remediation="Set 'MaxAuthTries 4' in /etc/ssh/sshd_config.d/ and reload sshd.",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.2.18",
)
def check(host: Host) -> Finding:
    return require_at_most(host, "maxauthtries", 4)


@fixer(check)
def fix(host: Host) -> list[Action]:
    return dropin_actions("60-hardening-maxauthtries.conf", ["MaxAuthTries 4"])
