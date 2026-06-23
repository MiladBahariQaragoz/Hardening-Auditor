"""The ``Host`` abstraction: how checks read facts from the system under audit.

Checks never call ``open()`` or ``subprocess`` directly. They ask an injected ``Host`` for
three things: the text of a file, the metadata of a file, and the result of running a
command. This indirection (ADR-0004) buys three things:

* **Testability** — tests pass a ``FakeHost`` with canned files/command output, so the full
  suite runs on any OS (including the Windows dev box) with no Linux required.
* **Retargetability** — ``LocalHost`` audits the machine it runs on today; a future
  ``RemoteHost`` could audit over SSH without touching a single check.
* **Debuggability** — every system access goes through one narrow, loggable surface.

``LocalHost`` is the only OS-touching implementation and is meant to run *on* the Linux
host being audited. Its Unix-only imports (``pwd``/``grp``) are deferred into the methods
that need them so this module imports cleanly on Windows for development and testing.
"""

from __future__ import annotations

import logging
import os
import stat as stat_module
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

log = logging.getLogger(__name__)

# Commands should never hang a run; cap every external call.
_COMMAND_TIMEOUT = 15


@dataclass(frozen=True)
class FileStat:
    """The subset of file metadata that permission/ownership checks need."""

    mode: int   # permission bits only, e.g. 0o640 (already masked with 0o777)
    uid: int
    gid: int
    owner: str  # resolved user name, or str(uid) if it cannot be resolved
    group: str  # resolved group name, or str(gid) if it cannot be resolved

    @property
    def mode_octal(self) -> str:
        """Permissions as a 4-digit octal string, e.g. ``0640``."""
        return f"{self.mode:04o}"


@dataclass(frozen=True)
class CommandResult:
    """The outcome of running a command on the host."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class Host(Protocol):
    """What a check is allowed to ask of the system under audit.

    Implementations must be read-only: nothing here mutates the host. Remediation goes
    through a separate, explicit path (see ``auditor.remediation``).
    """

    name: str

    def read_text(self, path: str) -> str | None:
        """Return the file's text, or ``None`` if it is missing/unreadable."""
        ...

    def stat(self, path: str) -> FileStat | None:
        """Return file metadata, or ``None`` if the path does not exist."""
        ...

    def run(self, argv: Sequence[str]) -> CommandResult:
        """Run a command (never via a shell) and capture its result."""
        ...


class LocalHost:
    """Audits the machine this process runs on. Intended to run on the target Linux host."""

    def __init__(self, name: str | None = None) -> None:
        if name:
            self.name = name
        elif hasattr(os, "uname"):  # Unix
            self.name = os.uname().nodename
        else:  # Windows dev box
            self.name = os.environ.get("COMPUTERNAME", "localhost")

    def read_text(self, path: str) -> str | None:
        try:
            return Path(path).read_text(encoding="utf-8", errors="replace")
        except (FileNotFoundError, IsADirectoryError, PermissionError, OSError) as exc:
            log.debug("read_text(%s) failed: %s", path, exc)
            return None

    def stat(self, path: str) -> FileStat | None:
        try:
            st = os.stat(path)
        except OSError as exc:
            log.debug("stat(%s) failed: %s", path, exc)
            return None
        mode = stat_module.S_IMODE(st.st_mode)
        return FileStat(
            mode=mode,
            uid=st.st_uid,
            gid=st.st_gid,
            owner=_resolve_owner(st.st_uid),
            group=_resolve_group(st.st_gid),
        )

    def run(self, argv: Sequence[str]) -> CommandResult:
        log.debug("run(%s)", " ".join(argv))
        try:
            proc = subprocess.run(  # noqa: S603 — argv list, never shell=True
                list(argv),
                capture_output=True,
                text=True,
                timeout=_COMMAND_TIMEOUT,
                check=False,
            )
        except FileNotFoundError:
            return CommandResult(returncode=127, stdout="", stderr=f"{argv[0]}: not found")
        except subprocess.TimeoutExpired:
            return CommandResult(returncode=124, stdout="", stderr=f"{argv[0]}: timed out")
        return CommandResult(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


def _resolve_owner(uid: int) -> str:
    try:
        import pwd  # Unix-only; deferred so this module imports on Windows

        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        return str(uid)


def _resolve_group(gid: int) -> str:
    try:
        import grp  # Unix-only; deferred so this module imports on Windows

        return grp.getgrgid(gid).gr_name
    except (ImportError, KeyError):
        return str(gid)
