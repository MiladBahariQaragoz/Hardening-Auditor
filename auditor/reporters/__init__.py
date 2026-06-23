"""Pluggable reporters: turn an ``AuditReport`` into a rendered string.

Each reporter exposes ``render(report: AuditReport) -> str``. ``get_reporter(name)`` maps a
CLI ``--report`` choice to the right one, so adding an output format is a one-line registry
edit here plus a new module — the engine and checks are untouched.
"""

from __future__ import annotations

from collections.abc import Callable

from ..models import AuditReport
from . import console, html, json, markdown

Reporter = Callable[[AuditReport], str]

_REPORTERS: dict[str, Reporter] = {
    "console": console.render,
    "json": json.render,
    "markdown": markdown.render,
    "html": html.render,
}

# CLI-friendly aliases (e.g. the README uses `--report md`).
_ALIASES = {"md": "markdown"}

# File extension per format, for the CLI's default output path.
FILE_EXTENSION = {"json": "json", "markdown": "md", "html": "html"}


def available() -> list[str]:
    return sorted(_REPORTERS)


def choices() -> list[str]:
    """Everything valid for the CLI's ``--report``: canonical names plus aliases."""
    return sorted(set(_REPORTERS) | set(_ALIASES))


def canonical(name: str) -> str:
    return _ALIASES.get(name, name)


def get_reporter(name: str) -> Reporter:
    try:
        return _REPORTERS[canonical(name)]
    except KeyError:
        raise ValueError(
            f"unknown report format {name!r}; available: {', '.join(available())}"
        ) from None
