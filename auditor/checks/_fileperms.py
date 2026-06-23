"""Shared helpers for "permissions on <file> are configured" controls (CIS 6.1.x etc.).

Underscore-prefixed: no control here. The CIS file-permission controls are all the same shape
— owner must be root, group must be in an allowed set, and the mode must be no more permissive
than a maximum — so the logic lives here once and each control module is a few lines.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding
from ..remediation import Action, SetMode, SetOwner


def perm_finding(
    host: Host,
    path: str,
    *,
    max_mode: int,
    owner: str = "root",
    groups: tuple[str, ...] = ("root",),
) -> Finding:
    """Pass iff ``path`` is owner-correct, group-allowed, and no more permissive than max_mode."""
    st = host.stat(path)
    if st is None:
        return Finding.skipped(detail=f"{path} not present / unreadable")

    problems: list[str] = []
    if st.owner != owner and str(st.uid) != owner:
        problems.append(f"owner {st.owner} (want {owner})")
    if st.group not in groups and str(st.gid) not in groups:
        problems.append(f"group {st.group} (want {'/'.join(groups)})")
    if st.mode & ~max_mode:
        problems.append(f"mode {st.mode_octal} (want <= {max_mode:04o})")

    expected = f"{owner}:{groups[0]} {max_mode:04o} or stricter"
    if problems:
        return Finding.failed(found="; ".join(problems), expected=expected)
    return Finding.passed(found=f"{st.owner}:{st.group} {st.mode_octal}", expected=expected)


def perm_actions(path: str, mode: int, owner: str = "root", group: str = "root") -> list[Action]:
    return [SetOwner(path, owner, group), SetMode(path, mode)]
