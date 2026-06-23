"""Tests for the SSH directive controls added in Phase 5 (5.2.5/6/9/11/12/14/15/16/18/21)."""

from __future__ import annotations

import pytest

from auditor.checks import (
    ssh_allow_tcp_forwarding,
    ssh_ignore_rhosts,
    ssh_kex,
    ssh_login_grace_time,
    ssh_loglevel,
    ssh_macs,
    ssh_max_auth_tries,
    ssh_permit_empty_passwords,
    ssh_use_pam,
    ssh_x11_forwarding,
)
from auditor.host import CommandResult
from auditor.models import Status
from auditor.remediation import RunCommand, WriteFile
from tests.fakes import FakeHost

MODULES = [
    ssh_loglevel,
    ssh_use_pam,
    ssh_permit_empty_passwords,
    ssh_ignore_rhosts,
    ssh_x11_forwarding,
    ssh_allow_tcp_forwarding,
    ssh_max_auth_tries,
    ssh_login_grace_time,
    ssh_macs,
    ssh_kex,
]

PASS_OUTPUT = {
    ssh_loglevel: "loglevel VERBOSE",
    ssh_use_pam: "usepam yes",
    ssh_permit_empty_passwords: "permitemptypasswords no",
    ssh_ignore_rhosts: "ignorerhosts yes",
    ssh_x11_forwarding: "x11forwarding no",
    ssh_allow_tcp_forwarding: "allowtcpforwarding no",
    ssh_max_auth_tries: "maxauthtries 4",
    ssh_login_grace_time: "logingracetime 60",
    ssh_macs: "macs hmac-sha2-512-etm@openssh.com",
    ssh_kex: "kexalgorithms curve25519-sha256",
}

FAIL_OUTPUT = {
    ssh_loglevel: "loglevel QUIET",
    ssh_use_pam: "usepam no",
    ssh_permit_empty_passwords: "permitemptypasswords yes",
    ssh_ignore_rhosts: "ignorerhosts no",
    ssh_x11_forwarding: "x11forwarding yes",
    ssh_allow_tcp_forwarding: "allowtcpforwarding yes",
    ssh_max_auth_tries: "maxauthtries 6",
    ssh_login_grace_time: "logingracetime 120",
    ssh_macs: "macs hmac-md5,hmac-sha2-256-etm@openssh.com",
    ssh_kex: "kexalgorithms diffie-hellman-group14-sha1",
}


def _sshd(output: str) -> dict:
    return {("sshd", "-T"): CommandResult(0, output + "\n", "")}


@pytest.mark.parametrize("mod", MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_pass_on_compliant_value(mod):
    assert mod.check(FakeHost(commands=_sshd(PASS_OUTPUT[mod]))).status is Status.PASS


@pytest.mark.parametrize("mod", MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_fail_on_bad_value(mod):
    assert mod.check(FakeHost(commands=_sshd(FAIL_OUTPUT[mod]))).status is Status.FAIL


@pytest.mark.parametrize("mod", MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_skip_when_no_sshd(mod):
    assert mod.check(FakeHost()).status is Status.SKIP


@pytest.mark.parametrize("mod", MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_fix_writes_dropin_and_validates_before_reload(mod):
    actions = mod.fix(FakeHost())
    assert any(isinstance(a, WriteFile) for a in actions)
    cmds = [a for a in actions if isinstance(a, RunCommand)]
    assert cmds[0].argv == ("sshd", "-t")  # validate first
    assert cmds[-1].argv == ("systemctl", "reload", "ssh")
