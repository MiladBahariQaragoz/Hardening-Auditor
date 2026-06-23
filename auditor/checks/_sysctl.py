"""Shared helpers for single-value sysctl controls (e.g. ASLR, core dumps).

Underscore-prefixed: no control here. Values are read from ``/proc/sys`` (the live kernel
state) and fixes are written as a drop-in under ``/etc/sysctl.d/`` plus ``sysctl --system``.
The composite network control (``sysctl_network.py``) has its own multi-parameter logic; this
helper serves the one-parameter controls.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding
from ..remediation import Action, RunCommand, WriteFile


def _proc_path(sysctl_key: str) -> str:
    return "/proc/sys/" + sysctl_key.replace(".", "/")


def expect(host: Host, sysctl_key: str, want: str) -> Finding:
    raw = host.read_text(_proc_path(sysctl_key))
    if raw is None:
        return Finding.skipped(detail=f"{sysctl_key} unreadable (/proc/sys)")
    value = raw.strip()
    if value == want:
        return Finding.passed(found=f"{sysctl_key}={value}", expected=f"{sysctl_key}={want}")
    return Finding.failed(found=f"{sysctl_key}={value}", expected=f"{sysctl_key}={want}")


def set_actions(sysctl_key: str, want: str, filename: str) -> list[Action]:
    content = f"# Managed by linux-hardening-auditor\n{sysctl_key} = {want}\n"
    return [
        WriteFile(f"/etc/sysctl.d/{filename}", content, mode=0o644),
        RunCommand(("sysctl", "--system"), f"apply {sysctl_key}"),
    ]
