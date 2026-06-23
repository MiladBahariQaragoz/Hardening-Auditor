"""``FakeHost`` — an in-memory ``Host`` for testing checks without a real Linux box.

A test wires up exactly the files, file metadata, and command outputs a check will look at,
then asserts on the ``Finding``. This is what lets the whole suite run on the Windows dev
machine (ADR-0004). Anything not explicitly configured behaves like "absent": files read as
``None``, commands return code 127 (not found).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from auditor.host import CommandResult, FileStat


class FakeHost:
    name = "fakehost"

    def __init__(
        self,
        *,
        files: dict[str, str] | None = None,
        stats: dict[str, FileStat] | None = None,
        commands: dict[tuple[str, ...], CommandResult] | None = None,
    ) -> None:
        self._files = files or {}
        self._stats = stats or {}
        self._commands = commands or {}

    def read_text(self, path: str) -> str | None:
        return self._files.get(path)

    def stat(self, path: str) -> FileStat | None:
        return self._stats.get(path)

    def run(self, argv: Sequence[str]) -> CommandResult:
        return self._commands.get(
            tuple(argv),
            CommandResult(returncode=127, stdout="", stderr=f"{argv[0]}: not found"),
        )


class FakeApplier:
    """An ``Applier`` that mutates a ``FakeHost`` in memory and records what it did.

    Mutating the same host the check reads lets a test exercise the whole
    plan -> apply -> verify loop: after a fix the re-run check sees the new state.
    """

    def __init__(self, host: FakeHost) -> None:
        self.host = host
        self.commands: list[tuple[str, ...]] = []
        self.backups: list[str] = []

    def backup(self, path: str) -> str | None:
        if path in self.host._files or path in self.host._stats:
            location = f"/backup{path}"
            self.backups.append(location)
            return location
        return None

    def write_file(self, path: str, content: str, mode: int | None) -> None:
        self.host._files[path] = content
        if mode is not None:
            self._set_stat(path, mode=mode)

    def set_mode(self, path: str, mode: int) -> None:
        self._set_stat(path, mode=mode)

    def set_owner(self, path: str, owner: str, group: str) -> None:
        uid = 0 if owner == "root" else 1000
        self._set_stat(path, owner=owner, group=group, uid=uid)

    def run(self, argv: Sequence[str]) -> tuple[int, str]:
        self.commands.append(tuple(argv))
        return 0, ""

    def _set_stat(self, path: str, **changes) -> None:
        current = self.host._stats.get(path) or FileStat(
            mode=0o644, uid=0, gid=0, owner="root", group="root"
        )
        if "uid" in changes:
            changes["gid"] = changes["uid"]
        self.host._stats[path] = replace(current, **changes)
