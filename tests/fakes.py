"""``FakeHost`` — an in-memory ``Host`` for testing checks without a real Linux box.

A test wires up exactly the files, file metadata, and command outputs a check will look at,
then asserts on the ``Finding``. This is what lets the whole suite run on the Windows dev
machine (ADR-0004). Anything not explicitly configured behaves like "absent": files read as
``None``, commands return code 127 (not found).
"""

from __future__ import annotations

from collections.abc import Sequence

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
