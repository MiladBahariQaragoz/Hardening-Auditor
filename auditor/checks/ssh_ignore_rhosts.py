"""CIS 5.2.11 — Ensure SSH IgnoreRhosts is enabled.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 5.2.11.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._ssh import dropin_actions, require_equals


@control(
    id="5.2.11",
    title="SSH IgnoreRhosts enabled",
    severity=Severity.MEDIUM,
    description="sshd must ignore .rhosts/.shosts trust files (IgnoreRhosts yes).",
    rationale=(
        "rhosts-style host trust grants login based only on the source host, no key or "
        "password. Honouring it lets an attacker who controls a 'trusted' host walk straight in."
    ),
    remediation="Set 'IgnoreRhosts yes' in /etc/ssh/sshd_config.d/ and reload sshd.",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 5.2.11",
)
def check(host: Host) -> Finding:
    return require_equals(host, "ignorerhosts", "yes", default_note="default yes")


@fixer(check)
def fix(host: Host) -> list[Action]:
    return dropin_actions("60-hardening-ignorerhosts.conf", ["IgnoreRhosts yes"])
