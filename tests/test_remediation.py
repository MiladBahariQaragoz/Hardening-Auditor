"""Remediation engine: planning, dry-run, and the apply -> verify loop."""

from __future__ import annotations

from pathlib import Path

from auditor import engine, remediation
from auditor.host import FileStat
from auditor.models import Status
from auditor.remediation import RunCommand, SetMode, WriteFile
from tests.fakes import FakeApplier, FakeHost


def test_dry_run_render_lists_actions_without_applying(catalogue):
    # A host whose /etc/shadow is world-readable -> shadow control fails and has a fixer.
    host = FakeHost(stats={"/etc/shadow": FileStat(0o644, 1000, 50, "bob", "staff")})
    report = engine.run(host)
    plans = remediation.plan(host, report.results)

    ids = [p.control.id for p in plans]
    assert "6.1.5" in ids
    text = remediation.render_dry_run(plans)
    assert "chmod 0640 /etc/shadow" in text
    assert "dry-run" in text


def test_plan_skips_controls_without_a_fixer(catalogue):
    # auditd has no fixer in this phase; it fails on a bare host but must not appear in a plan.
    host = FakeHost()
    plans = remediation.plan(host, engine.run(host).results)
    assert "4.1.1.2" not in [p.control.id for p in plans]


def test_apply_fixes_shadow_and_verifies_pass(catalogue):
    host = FakeHost(stats={"/etc/shadow": FileStat(0o644, 1000, 50, "bob", "staff")})
    plans = remediation.plan(host, engine.run(host).results)
    applier = FakeApplier(host)

    outcomes = remediation.apply(host, applier, plans)
    shadow = next(o for o in outcomes if o.control.id == "6.1.5")
    assert shadow.verified is Status.PASS
    assert shadow.ok
    assert shadow.backups  # the old file was backed up before being changed


def test_apply_sysctl_writes_dropin_and_runs_sysctl(catalogue):
    # All sysctl params present but wrong -> control fails and the fixer runs.
    # (We assert the apply *mechanics*: a fake applier can't simulate the kernel re-reading
    #  the drop-in, so /proc/sys verification is covered live on a real host instead.)
    from auditor.checks.sysctl_network import PARAMETERS

    bad = {path: "1\n" if want == "0" else "0\n" for _cid, path, want in PARAMETERS}
    host = FakeHost(files=bad)
    plans = remediation.plan(host, engine.run(host).results)
    applier = FakeApplier(host)

    remediation.apply(host, applier, plans)
    assert "/etc/sysctl.d/60-hardening-auditor.conf" in host._files
    assert "net.ipv4.ip_forward = 0" in host._files["/etc/sysctl.d/60-hardening-auditor.conf"]
    assert ("sysctl", "--system") in applier.commands


def test_failed_command_aborts_and_reports_error(catalogue):
    host = FakeHost(stats={"/etc/shadow": FileStat(0o644, 1000, 50, "bob", "staff")})

    class FailingApplier(FakeApplier):
        def run(self, argv):
            return 1, "boom"

    # Use a plan with a RunCommand so the failure path is exercised.
    plan = [
        remediation.ControlPlan(
            control=next(p.control for p in remediation.plan(host, engine.run(host).results)
                         if p.control.id == "6.1.5"),
            actions=[SetMode("/etc/shadow", 0o640), RunCommand(("false",), "boom")],
        )
    ]
    outcomes = remediation.apply(host, FailingApplier(host), plan)
    assert outcomes[0].error
    assert not outcomes[0].ok


def test_local_applier_backs_up_before_writing(tmp_path: Path):
    target = tmp_path / "conf"
    target.write_text("old\n", encoding="utf-8")
    backup_dir = tmp_path / "backups"
    applier = remediation.LocalApplier(backup_dir)

    location = applier.backup(str(target))
    applier.write_file(str(target), "new\n", mode=None)

    assert location is not None
    assert Path(location).read_text() == "old\n"
    assert target.read_text() == "new\n"
