"""CIS 6.1.5 — Ensure permissions on /etc/shadow are configured.

Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0, control 6.1.5.

CIS requires ``/etc/shadow`` to be owned by root, group ``shadow``, mode ``0640`` or more
restrictive. This check passes when there are no world permissions, no group write/execute,
no owner execute, and the owner is root — i.e. 0640/0600/0400/0440/0000 etc.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding, Severity
from ..registry import control

SHADOW = "/etc/shadow"
MAX_MODE = 0o640  # the most permissive mode that still passes


@control(
    id="6.1.5",
    title="/etc/shadow permissions <= 0640",
    severity=Severity.HIGH,
    description="/etc/shadow must be root-owned, group shadow, mode 0640 or stricter.",
    rationale=(
        "World- or group-readable password hashes hand an attacker offline cracking material — "
        "turning a low-privilege foothold into full credential compromise."
    ),
    remediation="chown root:shadow /etc/shadow && chmod 0640 /etc/shadow",
    benchmark="CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0 — 6.1.5",
)
def check(host: Host) -> Finding:
    st = host.stat(SHADOW)
    if st is None:
        return Finding.skipped(detail="/etc/shadow not present / unreadable")

    problems: list[str] = []
    if st.uid != 0:
        problems.append(f"owner {st.owner} (want root)")
    if st.group not in ("shadow", "root", "0"):
        problems.append(f"group {st.group} (want shadow)")
    # No world bits, no group write/exec, no owner exec → mode must be a subset of 0640.
    if st.mode & ~MAX_MODE:
        problems.append(f"mode {st.mode_octal} (want <= 0640)")

    expected = "root:shadow 0640 or stricter"
    if problems:
        return Finding.failed(found="; ".join(problems), expected=expected)
    return Finding.passed(found=f"{st.owner}:{st.group} {st.mode_octal}", expected=expected)
