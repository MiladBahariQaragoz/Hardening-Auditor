"""Shared helpers for ``/etc/login.defs`` controls (password-aging defaults, CIS 5.5.1.x).

Underscore-prefixed: no control here. ``login.defs`` is ``KEY value`` (whitespace-separated,
last setting wins). The helper reads an integer directive and plans a fix that sets it while
preserving the rest of the file.
"""

from __future__ import annotations

from ..host import Host
from ..remediation import Action, WriteFile

LOGIN_DEFS = "/etc/login.defs"


def get_int(host: Host, key: str) -> int | None:
    """The integer value of a login.defs directive (last one wins), or None if unset."""
    text = host.read_text(LOGIN_DEFS)
    if text is None:
        return None
    found: int | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] == key:
            try:
                found = int(parts[1])
            except ValueError:
                continue
    return found


def set_action(host: Host, key: str, value: int) -> list[Action]:
    """Plan to set ``key value`` in login.defs, replacing any existing line for that key."""
    current = host.read_text(LOGIN_DEFS) or ""
    out: list[str] = []
    replaced = False
    for raw in current.splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#") and stripped.split()[0] == key:
            out.append(f"{key}\t{value}")
            replaced = True
        else:
            out.append(raw)
    if not replaced:
        out.append(f"{key}\t{value}")
    return [WriteFile(LOGIN_DEFS, "\n".join(out) + "\n", mode=0o644)]
