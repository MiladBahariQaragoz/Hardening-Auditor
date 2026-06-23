"""Shared fixtures."""

from __future__ import annotations

import importlib
import pkgutil

import pytest

import auditor.checks as checks_pkg
from auditor import registry


@pytest.fixture
def catalogue():
    """Populate the global registry with the real control catalogue for this test.

    Other tests (e.g. the engine suite) clear the registry, and Python caches modules so a
    plain re-import won't re-run the ``@control``/``@fixer`` decorators. Reloading each check
    module re-executes them, guaranteeing a full, isolated catalogue regardless of test order.
    """
    registry.clear()
    for module in pkgutil.iter_modules(checks_pkg.__path__):
        mod = importlib.import_module(f"{checks_pkg.__name__}.{module.name}")
        importlib.reload(mod)
    yield
    registry.clear()
