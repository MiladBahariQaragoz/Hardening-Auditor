"""Tests for CIS 5.2.8 (SSH PermitRootLogin) and the shared sshd-config helper."""

from __future__ import annotations

from auditor.checks.ssh_permit_root_login import check
from auditor.host import CommandResult
from auditor.models import Status
from tests.fakes import FakeHost

SSHD_T = ("sshd", "-T")


def _sshd_t(output: str) -> dict:
    return {SSHD_T: CommandResult(returncode=0, stdout=output, stderr="")}


def test_pass_when_sshd_t_reports_no():
    host = FakeHost(commands=_sshd_t("permitrootlogin no\n"))
    result = check(host)
    assert result.status is Status.PASS
    assert result.found == "no"


def test_fail_when_sshd_t_reports_yes():
    host = FakeHost(commands=_sshd_t("permitrootlogin yes\n"))
    result = check(host)
    assert result.status is Status.FAIL
    assert result.found == "yes"
    assert result.expected == "no"


def test_fail_on_prohibit_password_which_still_allows_key_root_login():
    host = FakeHost(commands=_sshd_t("permitrootlogin prohibit-password\n"))
    assert check(host).status is Status.FAIL


def test_file_fallback_first_value_wins():
    # No sshd binary; parse the file. First occurrence is authoritative (sshd_config(5)).
    host = FakeHost(files={"/etc/ssh/sshd_config": "PermitRootLogin no\nPermitRootLogin yes\n"})
    assert check(host).status is Status.PASS


def test_file_fallback_fails_when_set_yes():
    host = FakeHost(files={"/etc/ssh/sshd_config": "# header\nPermitRootLogin yes\n"})
    assert check(host).status is Status.FAIL


def test_unset_in_file_fails_on_default():
    host = FakeHost(files={"/etc/ssh/sshd_config": "Port 22\n"})
    result = check(host)
    assert result.status is Status.FAIL
    assert "default" in result.found


def test_skip_when_no_sshd_anywhere():
    assert check(FakeHost()).status is Status.SKIP
