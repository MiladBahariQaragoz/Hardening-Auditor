from __future__ import annotations

from auditor.checks.firewall_active import check
from auditor.host import CommandResult
from auditor.models import Status
from tests.fakes import FakeHost


def test_pass_when_ufw_active():
    cmds = {("ufw", "status"): CommandResult(0, "Status: active\n", "")}
    assert check(FakeHost(commands=cmds)).status is Status.PASS


def test_pass_when_nftables_active_without_ufw():
    cmds = {("systemctl", "is-active", "nftables"): CommandResult(0, "active\n", "")}
    assert check(FakeHost(commands=cmds)).status is Status.PASS


def test_fail_when_ufw_inactive():
    cmds = {("ufw", "status"): CommandResult(0, "Status: inactive\n", "")}
    r = check(FakeHost(commands=cmds))
    assert r.status is Status.FAIL
    assert "inactive" in r.found


def test_fail_when_no_firewall_at_all():
    assert check(FakeHost()).status is Status.FAIL
