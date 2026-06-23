from __future__ import annotations

from auditor.checks.shadow_perms import check
from auditor.host import FileStat
from auditor.models import Status
from tests.fakes import FakeHost

SHADOW = "/etc/shadow"


def _stat(mode: int, uid: int = 0, group: str = "shadow") -> dict:
    return {SHADOW: FileStat(mode=mode, uid=uid, gid=42, owner="root", group=group)}


def test_pass_at_0640_root_shadow():
    assert check(FakeHost(stats=_stat(0o640))).status is Status.PASS


def test_pass_when_stricter_than_required():
    assert check(FakeHost(stats=_stat(0o600))).status is Status.PASS
    assert check(FakeHost(stats=_stat(0o000))).status is Status.PASS


def test_fail_when_world_readable():
    r = check(FakeHost(stats=_stat(0o644)))
    assert r.status is Status.FAIL
    assert "0644" in r.found


def test_fail_when_not_root_owned():
    r = check(FakeHost(stats=_stat(0o640, uid=1000)))
    assert r.status is Status.FAIL
    assert "owner" in r.found


def test_fail_on_wrong_group():
    r = check(FakeHost(stats=_stat(0o640, group="staff")))
    assert r.status is Status.FAIL
    assert "group" in r.found


def test_skip_when_absent():
    assert check(FakeHost()).status is Status.SKIP
