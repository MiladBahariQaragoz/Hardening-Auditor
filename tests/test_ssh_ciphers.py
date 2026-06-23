from __future__ import annotations

from auditor.checks.ssh_ciphers import check
from auditor.host import CommandResult
from auditor.models import Status
from tests.fakes import FakeHost


def _sshd_t(output: str) -> dict:
    return {("sshd", "-T"): CommandResult(0, output, "")}


def test_pass_with_only_strong_ciphers():
    strong = "ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr\n"
    assert check(FakeHost(commands=_sshd_t(strong))).status is Status.PASS


def test_fail_when_a_weak_cbc_cipher_is_offered():
    mixed = "ciphers aes256-ctr,aes128-cbc\n"
    r = check(FakeHost(commands=_sshd_t(mixed)))
    assert r.status is Status.FAIL
    assert "aes128-cbc" in r.found


def test_fail_when_unset():
    r = check(FakeHost(files={"/etc/ssh/sshd_config": "Port 22\n"}))
    assert r.status is Status.FAIL
    assert "unset" in r.found


def test_skip_when_no_sshd():
    assert check(FakeHost()).status is Status.SKIP
