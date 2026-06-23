"""CIS 1.9 — Ensure updates, patches, and additional security software are installed.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 1.9.

CIS 1.9 is about keeping the system patched. On Ubuntu the standard, auditable mechanism is
the ``unattended-upgrades`` package driven by APT periodic settings. This check verifies that
automatic package-list updates and unattended upgrades are both switched on in
``/etc/apt/apt.conf.d/`` (the conventional file is ``20auto-upgrades``).
"""

from __future__ import annotations

import re

from ..host import Host
from ..models import Finding, Severity
from ..registry import control, fixer
from ..remediation import Action, RunCommand, WriteFile

AUTO_UPGRADES = "/etc/apt/apt.conf.d/20auto-upgrades"
_AUTO_UPGRADES_CONTENT = (
    'APT::Periodic::Update-Package-Lists "1";\n'
    'APT::Periodic::Unattended-Upgrade "1";\n'
)
_DIRECTIVE = r'APT::Periodic::{key}\s+"(\d+)"\s*;'


@control(
    id="1.9",
    title="Automatic security updates enabled",
    severity=Severity.MEDIUM,
    description="unattended-upgrades must apply security updates automatically.",
    rationale=(
        "Most breaches exploit known, already-patched vulnerabilities. Automatic security "
        "updates close the window between a fix shipping and an operator getting around to it."
    ),
    remediation=(
        "apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades "
        '(ensures /etc/apt/apt.conf.d/20auto-upgrades sets Update-Package-Lists "1" and '
        'Unattended-Upgrade "1").'
    ),
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 1.9 (via unattended-upgrades)",
)
def check(host: Host) -> Finding:
    text = host.read_text(AUTO_UPGRADES)
    if text is None:
        return Finding.failed(found="20auto-upgrades missing", expected="both directives = 1")

    update = _directive(text, "Update-Package-Lists")
    upgrade = _directive(text, "Unattended-Upgrade")
    if update == 1 and upgrade == 1:
        return Finding.passed(found="update=1, upgrade=1", expected="both directives = 1")
    return Finding.failed(
        found=f"update={update}, upgrade={upgrade}",
        expected="both directives = 1",
    )


@fixer(check)
def fix(host: Host) -> list[Action]:
    return [
        RunCommand(
            ("apt-get", "install", "-y", "unattended-upgrades"),
            "install unattended-upgrades",
        ),
        WriteFile(AUTO_UPGRADES, _AUTO_UPGRADES_CONTENT, mode=0o644),
    ]


def _directive(text: str, key: str) -> int | None:
    match = re.search(_DIRECTIVE.format(key=re.escape(key)), text)
    return int(match.group(1)) if match else None
