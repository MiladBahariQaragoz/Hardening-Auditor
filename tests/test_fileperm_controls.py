"""Tests for the stat-based file-permission controls (5.2.1, 6.1.1, 6.1.3, 6.1.7, 5.1.2)."""

from __future__ import annotations

import pytest

from auditor.checks import (
    crontab_perms,
    group_perms,
    gshadow_perms,
    passwd_perms,
    ssh_sshd_config_perms,
)
from auditor.host import FileStat
from auditor.models import Status
from auditor.remediation import SetMode
from tests.fakes import FakeHost

# (module, path, a compliant mode, a too-permissive mode)
CASES = [
    (ssh_sshd_config_perms, "/etc/ssh/sshd_config", 0o600, 0o644, "root"),
    (passwd_perms, "/etc/passwd", 0o644, 0o666, "root"),
    (group_perms, "/etc/group", 0o644, 0o666, "root"),
    (gshadow_perms, "/etc/gshadow", 0o640, 0o644, "shadow"),
    (crontab_perms, "/etc/crontab", 0o600, 0o644, "root"),
]


@pytest.mark.parametrize("mod,path,ok_mode,bad_mode,group", CASES, ids=lambda v: str(v))
def test_pass_on_compliant_perms(mod, path, ok_mode, bad_mode, group):
    host = FakeHost(stats={path: FileStat(ok_mode, 0, 0, "root", group)})
    assert mod.check(host).status is Status.PASS


@pytest.mark.parametrize("mod,path,ok_mode,bad_mode,group", CASES, ids=lambda v: str(v))
def test_fail_when_too_permissive(mod, path, ok_mode, bad_mode, group):
    host = FakeHost(stats={path: FileStat(bad_mode, 0, 0, "root", group)})
    assert mod.check(host).status is Status.FAIL


@pytest.mark.parametrize("mod,path,ok_mode,bad_mode,group", CASES, ids=lambda v: str(v))
def test_fail_when_not_root_owned(mod, path, ok_mode, bad_mode, group):
    host = FakeHost(stats={path: FileStat(ok_mode, 1000, 0, "bob", group)})
    assert mod.check(host).status is Status.FAIL


@pytest.mark.parametrize("mod,path,ok_mode,bad_mode,group", CASES, ids=lambda v: str(v))
def test_skip_when_absent(mod, path, ok_mode, bad_mode, group):
    assert mod.check(FakeHost()).status is Status.SKIP


@pytest.mark.parametrize("mod,path,ok_mode,bad_mode,group", CASES, ids=lambda v: str(v))
def test_fix_sets_target_mode(mod, path, ok_mode, bad_mode, group):
    actions = mod.fix(FakeHost())
    assert SetMode(path, ok_mode) in actions
