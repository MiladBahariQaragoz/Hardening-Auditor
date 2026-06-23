from __future__ import annotations

from auditor.checks.auditd_enabled import check
from auditor.host import CommandResult
from auditor.models import Status
from tests.fakes import FakeHost


def _systemctl(active: str, enabled: str) -> dict:
    return {
        ("systemctl", "is-active", "auditd"): CommandResult(0, active + "\n", ""),
        ("systemctl", "is-enabled", "auditd"): CommandResult(0, enabled + "\n", ""),
    }


def test_pass_when_active_and_enabled():
    assert check(FakeHost(commands=_systemctl("active", "enabled"))).status is Status.PASS


def test_fail_when_inactive():
    r = check(FakeHost(commands=_systemctl("inactive", "enabled")))
    assert r.status is Status.FAIL
    assert "inactive" in r.found


def test_fail_when_not_installed():
    # systemctl missing entirely -> empty states -> treated as not installed.
    r = check(FakeHost())
    assert r.status is Status.FAIL
    assert "not installed" in r.found
