"""The control registry and the ``@control`` decorator.

This is the *only* place that knows individual checks exist. A check module declares its
control metadata with ``@control(...)`` and is registered the moment the module is imported
(ADR-0001). The engine asks the registry what to run; it never names a control itself, so
adding control #N touches only its own file — never this module, the engine, or a reporter.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .host import Host
from .models import Control, Finding, Severity

if TYPE_CHECKING:
    from .remediation import Action

log = logging.getLogger(__name__)

# A check is a function that inspects a host and returns a verdict with evidence.
CheckFunc = Callable[[Host], Finding]

# A fixer plans (does not perform) the actions that would make a failing control pass.
# It reads from the Host only; the remediation engine executes the actions with backups.
FixFunc = Callable[[Host], "list[Action]"]


@dataclass(frozen=True)
class RegisteredCheck:
    """A control paired with the function that evaluates it."""

    control: Control
    func: CheckFunc


# The single global registry. Modules append to it at import time via @control.
_REGISTRY: dict[str, RegisteredCheck] = {}

# Optional remediation functions, keyed by control id. A control can exist without a fixer
# (audit-only); a fixer cannot exist without its control (enforced in @fixer).
_FIXERS: dict[str, FixFunc] = {}


def control(
    *,
    id: str,
    title: str,
    severity: Severity,
    description: str,
    rationale: str = "",
    remediation: str = "",
    benchmark: str = "",
) -> Callable[[CheckFunc], CheckFunc]:
    """Decorate a check function, registering it under its CIS control ``id``.

    Usage in a check module::

        @control(id="5.2.8", title="SSH PermitRootLogin no", severity=Severity.HIGH, ...)
        def check(host: Host) -> Finding:
            ...
    """

    def decorator(func: CheckFunc) -> CheckFunc:
        if id in _REGISTRY:
            raise ValueError(
                f"duplicate control id {id!r}: already registered by "
                f"{_REGISTRY[id].func.__module__}"
            )
        ctrl = Control(
            id=id,
            title=title,
            severity=severity,
            description=description,
            rationale=rationale,
            remediation=remediation,
            benchmark=benchmark,
        )
        _REGISTRY[id] = RegisteredCheck(control=ctrl, func=func)
        func.control = ctrl  # type: ignore[attr-defined]  # handy for tests
        log.debug("registered control %s (%s)", id, func.__module__)
        return func

    return decorator


def fixer(check_func: Any) -> Callable[[FixFunc], FixFunc]:
    """Register a remediation function for the control owned by ``check_func``.

    Used in a check module right after its ``@control`` check, so the id is never repeated::

        @control(id="6.1.5", ...)
        def check(host): ...

        @fixer(check)
        def fix(host) -> list[Action]:
            return [SetMode("/etc/shadow", 0o640), ...]
    """
    control_id = check_func.control.id

    def decorator(fix_func: FixFunc) -> FixFunc:
        _FIXERS[control_id] = fix_func
        log.debug("registered fixer for control %s", control_id)
        return fix_func

    return decorator


def all_checks() -> list[RegisteredCheck]:
    """Every registered check, in a deterministic order (by CIS id, numerically aware)."""
    return sorted(_REGISTRY.values(), key=lambda rc: id_sort_key(rc.control.id))


def fixer_for(control_id: str) -> FixFunc | None:
    """The remediation function for a control id, or ``None`` if it's audit-only."""
    return _FIXERS.get(control_id)


def check_for(control_id: str) -> RegisteredCheck | None:
    """The registered check for a control id (used to re-verify after a fix)."""
    return _REGISTRY.get(control_id)


def clear() -> None:
    """Empty the registry. Test-only — keeps test cases isolated from one another."""
    _REGISTRY.clear()
    _FIXERS.clear()


def id_sort_key(cid: str) -> list[tuple[int, int, str]]:
    """Sort key that orders CIS ids numerically: ``5.2.10`` after ``5.2.9``, not before.

    Each dot-separated part becomes ``(0, int, "")`` if numeric, else ``(1, 0, text)`` so
    numeric parts sort before non-numeric placeholders like ``x`` deterministically.
    """
    key: list[tuple[int, int, str]] = []
    for part in cid.split("."):
        if part.isdigit():
            key.append((0, int(part), ""))
        else:
            key.append((1, 0, part))
    return key
