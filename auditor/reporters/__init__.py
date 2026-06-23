"""Pluggable reporters: turn an ``AuditReport`` into a rendered string.

Each reporter exposes ``render(report: AuditReport) -> str``. ``get_reporter(name)`` maps a
CLI ``--report`` choice to the right one, so adding an output format is a one-line registry
edit here plus a new module — the engine and checks are untouched.
"""

from __future__ import annotations

from collections.abc import Callable

from ..models import AuditReport
from . import console, json

Reporter = Callable[[AuditReport], str]

_REPORTERS: dict[str, Reporter] = {
    "console": console.render,
    "json": json.render,
}


def available() -> list[str]:
    return sorted(_REPORTERS)


def get_reporter(name: str) -> Reporter:
    try:
        return _REPORTERS[name]
    except KeyError:
        raise ValueError(
            f"unknown report format {name!r}; available: {', '.join(available())}"
        ) from None
