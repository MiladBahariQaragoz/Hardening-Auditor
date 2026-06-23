"""Reporter tests: output is deterministic, grouped, and complete."""

from __future__ import annotations

import json as _json

from auditor.models import AuditReport, CheckResult, Control, Finding, Severity, Status
from auditor.reporters import console, json as json_reporter


def _report() -> AuditReport:
    high_fail = CheckResult(
        Control("5.2.8", "SSH PermitRootLogin no", Severity.HIGH, "desc", remediation="set no"),
        Finding.failed(found="yes", expected="no"),
    )
    med_pass = CheckResult(
        Control("3.3.1", "sysctl hardening", Severity.MEDIUM, "desc"),
        Finding.passed(),
    )
    return AuditReport(
        host="ubuntu-host",
        timestamp="2026-06-23T12:00:00",
        results=[med_pass, high_fail],  # deliberately out of order
    )


def test_console_groups_by_severity_high_first():
    out = console.render(_report())
    assert "ubuntu-host" in out
    assert "Score: 50%  (1 / 2 controls passing)" in out
    # HIGH section must appear before MEDIUM regardless of input order.
    assert out.index("HIGH") < out.index("MEDIUM")
    assert 'found "yes", expected "no"' in out


def test_console_is_deterministic():
    r = _report()
    assert console.render(r) == console.render(r)


def test_json_is_valid_and_sorted_by_id():
    out = json_reporter.render(_report())
    data = _json.loads(out)
    assert data["score"] == 50
    assert [r["id"] for r in data["results"]] == ["3.3.1", "5.2.8"]
    fail = next(r for r in data["results"] if r["id"] == "5.2.8")
    assert fail["status"] == "fail"
    assert fail["remediation"] == "set no"
