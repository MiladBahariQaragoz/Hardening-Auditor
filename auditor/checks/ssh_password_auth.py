"""SSH key-only authentication — ``PasswordAuthentication no``.

NOTE ON MAPPING: disabling password authentication is **not** a discrete control in the CIS
Ubuntu 22.04 v1.0.0 benchmark (CIS deliberately allows password+MFA setups). It is included
here as a deliberate hardening best-practice that goes beyond CIS, aligned with BSI
IT-Grundschutz SYS.1.3 (use key-based authentication). Being explicit that this exceeds CIS —
rather than mislabelling it as a CIS line item — is the honest, auditable choice.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action
from ._ssh import dropin_actions, effective_config


@control(
    id="5.2-BP-keyonly",
    title="SSH key-only auth (PasswordAuthentication no)",
    severity=Severity.HIGH,
    description="sshd must reject password logins, requiring SSH keys.",
    rationale=(
        "Passwords are guessable and reused; SSH is the most-attacked service on the public "
        "internet. Key-only auth makes online brute force infeasible."
    ),
    remediation=(
        "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config (ensure key access works "
        "first!), then reload sshd: systemctl reload ssh."
    ),
    benchmark="Hardening best practice beyond CIS v1.0.0; BSI IT-Grundschutz SYS.1.3 (key auth)",
)
def check(host: Host) -> Finding:
    config, _source = effective_config(host)
    if config is None:
        return Finding.skipped(detail="sshd not present / config unreadable")

    value = config.get("passwordauthentication")
    if value is None:
        return Finding.failed(found="unset (default: yes)", expected="no")
    if value.lower() == "no":
        return Finding.passed(found=value, expected="no")
    return Finding.failed(found=value, expected="no")


@fixer(check)
def fix(host: Host) -> list[Action]:
    # NOTE: disabling password auth can lock out users who lack a working SSH key. The drop-in
    # is written and validated with `sshd -t` before reload, but operators must ensure key
    # access works first (the remediation text says so).
    return dropin_actions("60-hardening-passwordauth.conf", ["PasswordAuthentication no"])
