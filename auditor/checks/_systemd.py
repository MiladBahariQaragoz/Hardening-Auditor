"""Shared systemd helpers for service-state controls.

Underscore-prefixed: declares no control, the engine skips it. ``systemctl is-active`` and
``is-enabled`` print the state on **stdout** (and return non-zero when the unit isn't
active/enabled), so these helpers read stdout and ignore the exit code. When systemctl is
missing or the unit is unknown, stdout is empty and the helpers return ``''`` — never the
"command not found" text from stderr, which would be mistaken for a state.
"""

from __future__ import annotations

from ..host import Host


def active_state(host: Host, unit: str) -> str:
    """e.g. 'active', 'inactive', 'failed', or '' (unit unknown / systemctl missing)."""
    return host.run(["systemctl", "is-active", unit]).stdout.strip()


def enabled_state(host: Host, unit: str) -> str:
    """e.g. 'enabled', 'disabled', 'masked', or '' (unit unknown / systemctl missing)."""
    return host.run(["systemctl", "is-enabled", unit]).stdout.strip()


def is_active(host: Host, unit: str) -> bool:
    return active_state(host, unit) == "active"
