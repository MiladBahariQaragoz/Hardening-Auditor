from __future__ import annotations

from auditor.checks.disabled_services import check
from auditor.host import CommandResult
from auditor.models import Status
from tests.fakes import FakeHost


def _active(*units: str) -> dict:
    return {
        ("systemctl", "is-active", unit): CommandResult(0, "active\n", "") for unit in units
    }


def test_pass_when_no_legacy_service_active():
    # Nothing configured -> all deny-listed units report no state -> pass.
    assert check(FakeHost()).status is Status.PASS


def test_fail_lists_active_offenders():
    r = check(FakeHost(commands=_active("telnet.socket", "vsftpd")))
    assert r.status is Status.FAIL
    assert "telnet.socket" in r.found
    assert "vsftpd" in r.found


def test_inactive_offender_does_not_fail():
    cmds = {("systemctl", "is-active", "cups"): CommandResult(0, "inactive\n", "")}
    assert check(FakeHost(commands=cmds)).status is Status.PASS
