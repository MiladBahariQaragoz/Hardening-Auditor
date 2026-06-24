"""Remediation engine: planning, dry-run, and the apply -> verify loop."""

from __future__ import annotations

from pathlib import Path

from auditor import engine, remediation
from auditor.host import FileStat
from auditor.models import Status
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


def test_audit_only_control_has_no_fixer(catalogue):
    # §2.2 (disable arbitrary services) is intentionally audit-only — auto-disabling unknown
    # services isn't a safe automatic action — so it must have no registered fixer.
    from auditor import registry

    assert registry.fixer_for("§2.2") is None
    assert registry.fixer_for("6.1.5") is not None  # control point: fixable ones do have one


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


def test_apply_unattended_upgrades_installs_and_verifies(catalogue):
    # File absent -> control fails; fixer runs apt install + writes the config; verify passes.
    host = FakeHost()
    plans = remediation.plan(host, engine.run(host).results)
    applier = FakeApplier(host)

    outcomes = remediation.apply(host, applier, plans)
    uu = next(o for o in outcomes if o.control.id == "1.9")
    assert uu.verified is Status.PASS
    assert any(argv[:3] == ("apt-get", "install", "-y") for argv in applier.commands)


def test_two_controls_editing_same_file_both_verify(catalogue):
    # Regression for the GCP-demo bug: 5.5.1.1 and 5.5.1.2 both rewrite /etc/login.defs.
    # With up-front planning the second write clobbered the first with stale content; apply must
    # re-derive each fixer against the live host so both end up correct.
    host = FakeHost(files={"/etc/login.defs": "PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\n"})
    plans = remediation.plan(host, engine.run(host).results)
    applier = FakeApplier(host)

    outcomes = remediation.apply(host, applier, plans)
    by_id = {o.control.id: o for o in outcomes}
    assert by_id["5.5.1.1"].verified is Status.PASS
    assert by_id["5.5.1.2"].verified is Status.PASS
    # Final file must satisfy both directives at once.
    final = host._files["/etc/login.defs"]
    assert "PASS_MAX_DAYS\t365" in final
    assert "PASS_MIN_DAYS\t1" in final


def test_failed_command_aborts_and_reports_error(catalogue):
    # 1.9's fixer runs `apt-get install ...`; when that command fails, apply must abort that
    # control and record the error rather than reporting it as fixed. (Actions are re-derived
    # from the live host at apply time, so the failure path is exercised through a real fixer.)
    host = FakeHost()

    class FailingApplier(FakeApplier):
        def run(self, argv):
            return 1, "boom"

    plans = remediation.plan(host, engine.run(host).results)
    outcomes = remediation.apply(host, FailingApplier(host), plans)
    uu = next(o for o in outcomes if o.control.id == "1.9")
    assert uu.error
    assert not uu.ok


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
