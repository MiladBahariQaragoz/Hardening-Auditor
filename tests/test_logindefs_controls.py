"""Tests for the login.defs password-aging controls (5.5.1.1/2/3)."""

from __future__ import annotations

from auditor.checks import pass_max_days, pass_min_days, pass_warn_age
from auditor.models import Status
from auditor.remediation import WriteFile
from tests.fakes import FakeHost

DEFS = "/etc/login.defs"


def _host(text: str) -> FakeHost:
    return FakeHost(files={DEFS: text})


def test_pass_max_days_pass_and_fail():
    assert pass_max_days.check(_host("PASS_MAX_DAYS 365\n")).status is Status.PASS
    assert pass_max_days.check(_host("PASS_MAX_DAYS 99999\n")).status is Status.FAIL


def test_pass_min_days_pass_and_fail():
    assert pass_min_days.check(_host("PASS_MIN_DAYS 1\n")).status is Status.PASS
    assert pass_min_days.check(_host("PASS_MIN_DAYS 0\n")).status is Status.FAIL


def test_pass_warn_age_pass_and_fail():
    assert pass_warn_age.check(_host("PASS_WARN_AGE 7\n")).status is Status.PASS
    assert pass_warn_age.check(_host("PASS_WARN_AGE 3\n")).status is Status.FAIL


def test_unset_directive_fails():
    assert pass_max_days.check(_host("# nothing\n")).status is Status.FAIL


def test_fix_sets_directive_preserving_other_lines():
    host = _host("PASS_MAX_DAYS 99999\nUMASK 022\n")
    write = next(a for a in pass_max_days.fix(host) if isinstance(a, WriteFile))
    assert "PASS_MAX_DAYS\t365" in write.content
    assert "UMASK 022" in write.content
    assert "99999" not in write.content
