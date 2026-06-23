from __future__ import annotations

from auditor.checks.ssh_password_auth import check
from auditor.host import CommandResult
from auditor.models import Status
from tests.fakes import FakeHost


def _sshd_t(output: str) -> dict:
    return {("sshd", "-T"): CommandResult(0, output, "")}


def test_pass_when_password_auth_no():
    assert check(FakeHost(commands=_sshd_t("passwordauthentication no\n"))).status is Status.PASS


def test_fail_when_password_auth_yes():
    r = check(FakeHost(commands=_sshd_t("passwordauthentication yes\n")))
    assert r.status is Status.FAIL
    assert r.expected == "no"


def test_fail_when_unset_defaults_to_yes():
    r = check(FakeHost(files={"/etc/ssh/sshd_config": "Port 22\n"}))
    assert r.status is Status.FAIL
    assert "default" in r.found


def test_skip_when_no_sshd():
    assert check(FakeHost()).status is Status.SKIP
