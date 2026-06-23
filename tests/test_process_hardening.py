"""Tests for the process-hardening, cron, and AppArmor controls (1.5.1, 1.5.4, 5.1.1, 1.3.1)."""

from __future__ import annotations

from auditor.checks import aslr, apparmor_enabled, core_dumps, cron_enabled
from auditor.host import CommandResult
from auditor.models import Status
from auditor.remediation import RunCommand, WriteFile
from tests.fakes import FakeHost


def test_aslr_pass_fail_skip():
    assert aslr.check(FakeHost(files={"/proc/sys/kernel/randomize_va_space": "2\n"})).status is Status.PASS
    assert aslr.check(FakeHost(files={"/proc/sys/kernel/randomize_va_space": "0\n"})).status is Status.FAIL
    assert aslr.check(FakeHost()).status is Status.SKIP


def test_aslr_fix_writes_dropin_and_applies():
    actions = aslr.fix(FakeHost())
    assert any(isinstance(a, WriteFile) and "randomize_va_space = 2" in a.content for a in actions)
    assert any(isinstance(a, RunCommand) and a.argv == ("sysctl", "--system") for a in actions)


def test_core_dumps_pass_fail():
    assert core_dumps.check(FakeHost(files={"/proc/sys/fs/suid_dumpable": "0\n"})).status is Status.PASS
    assert core_dumps.check(FakeHost(files={"/proc/sys/fs/suid_dumpable": "2\n"})).status is Status.FAIL


def test_cron_enabled_pass_fail():
    cmds = {
        ("systemctl", "is-active", "cron"): CommandResult(0, "active\n", ""),
        ("systemctl", "is-enabled", "cron"): CommandResult(0, "enabled\n", ""),
    }
    assert cron_enabled.check(FakeHost(commands=cmds)).status is Status.PASS
    assert cron_enabled.check(FakeHost()).status is Status.FAIL


def test_apparmor_pass_fail_and_is_audit_only():
    assert apparmor_enabled.check(FakeHost(files={apparmor_enabled.APPARMOR_FLAG: "Y\n"})).status is Status.PASS
    assert apparmor_enabled.check(FakeHost(files={apparmor_enabled.APPARMOR_FLAG: "N\n"})).status is Status.FAIL
    assert apparmor_enabled.check(FakeHost()).status is Status.FAIL
    # Audit-only: no fixer registered (enabling AppArmor needs a reboot).
    assert not hasattr(apparmor_enabled, "fix")
