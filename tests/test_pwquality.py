from __future__ import annotations

from auditor.checks.pwquality import check
from auditor.models import Status
from tests.fakes import FakeHost

CONF = "/etc/security/pwquality.conf"


def test_pass_when_minlen_meets_requirement():
    assert check(FakeHost(files={CONF: "minlen = 14\n"})).status is Status.PASS


def test_pass_when_minlen_exceeds_requirement():
    assert check(FakeHost(files={CONF: "minlen = 16\n"})).status is Status.PASS


def test_fail_when_minlen_too_small():
    r = check(FakeHost(files={CONF: "minlen = 8\n"}))
    assert r.status is Status.FAIL
    assert "8" in r.found


def test_last_value_wins():
    assert check(FakeHost(files={CONF: "minlen = 8\nminlen = 14\n"})).status is Status.PASS


def test_fail_when_minlen_unset():
    assert check(FakeHost(files={CONF: "# nothing here\n"})).status is Status.FAIL


def test_fail_when_conf_missing():
    r = check(FakeHost())
    assert r.status is Status.FAIL
    assert "missing" in r.found
