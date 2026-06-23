"""Unit tests for individual control fixers (the pure plan -> actions step)."""

from __future__ import annotations

from auditor.checks import (
    auditd_enabled,
    firewall_active,
    pwquality,
    shadow_perms,
    ssh_ciphers,
    ssh_permit_root_login,
    unattended_upgrades,
)
from auditor.remediation import RunCommand, SetMode, SetOwner, WriteFile
from tests.fakes import FakeHost


def test_ssh_permitrootlogin_fix_writes_dropin_validates_and_reloads():
    actions = ssh_permit_root_login.fix(FakeHost())
    write = next(a for a in actions if isinstance(a, WriteFile))
    assert write.path.endswith("sshd_config.d/60-hardening-permitrootlogin.conf")
    assert "PermitRootLogin no" in write.content
    # Validation must come before the reload so a bad config never takes SSH down.
    cmds = [a for a in actions if isinstance(a, RunCommand)]
    assert cmds[0].argv == ("sshd", "-t")
    assert cmds[1].argv == ("systemctl", "reload", "ssh")


def test_ssh_ciphers_fix_installs_only_strong_ciphers():
    write = next(a for a in ssh_ciphers.fix(FakeHost()) if isinstance(a, WriteFile))
    assert "Ciphers " in write.content
    assert "cbc" not in write.content  # no CBC ciphers in the remediation


def test_shadow_fix_sets_owner_then_mode():
    actions = shadow_perms.fix(FakeHost())
    assert SetOwner("/etc/shadow", "root", "shadow") in actions
    assert SetMode("/etc/shadow", 0o640) in actions


def test_pwquality_fix_preserves_other_settings():
    host = FakeHost(files={"/etc/security/pwquality.conf": "minlen = 6\ndcredit = -1\n"})
    write = next(a for a in pwquality.fix(host) if isinstance(a, WriteFile))
    assert "minlen = 14" in write.content
    assert "dcredit = -1" in write.content  # untouched
    assert "minlen = 6" not in write.content


def test_pwquality_fix_appends_when_absent():
    host = FakeHost(files={"/etc/security/pwquality.conf": "# empty\n"})
    write = next(a for a in pwquality.fix(host) if isinstance(a, WriteFile))
    assert "minlen = 14" in write.content


def test_firewall_fix_allows_ssh_before_enabling():
    cmds = [a.argv for a in firewall_active.fix(FakeHost()) if isinstance(a, RunCommand)]
    allow_ssh = cmds.index(("ufw", "allow", "OpenSSH"))
    enable = cmds.index(("ufw", "--force", "enable"))
    assert allow_ssh < enable  # never enable default-deny before SSH is allowed


def test_auditd_fix_installs_and_enables():
    cmds = [a.argv for a in auditd_enabled.fix(FakeHost()) if isinstance(a, RunCommand)]
    assert ("systemctl", "enable", "--now", "auditd") in cmds


def test_unattended_upgrades_fix_writes_both_directives():
    write = next(a for a in unattended_upgrades.fix(FakeHost()) if isinstance(a, WriteFile))
    assert 'Update-Package-Lists "1"' in write.content
    assert 'Unattended-Upgrade "1"' in write.content
