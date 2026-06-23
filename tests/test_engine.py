"""Engine + registry contract tests, using ad-hoc checks so they don't depend on any
specific control module."""

from __future__ import annotations

import pytest

from auditor import engine, registry
from auditor.models import Finding, Severity, Status
from tests.fakes import FakeHost


@pytest.fixture(autouse=True)
def clean_registry():
    """Each test starts with an empty registry and leaves it empty."""
    registry.clear()
    yield
    registry.clear()


def _register(cid: str, *, severity=Severity.HIGH):
    @registry.control(
        id=cid,
        title=f"control {cid}",
        severity=severity,
        description="test control",
    )
    def check(host):  # noqa: ARG001
        return Finding.passed(found="ok")

    return check


def test_passing_check_produces_pass_result():
    _register("1.1")
    report = engine.run(FakeHost(), checks=registry.all_checks(), timestamp="2026-06-23T00:00:00")
    assert report.total == 1
    assert report.passed == 1
    assert report.score == 100
    assert report.results[0].status is Status.PASS


def test_raising_check_is_captured_as_error_not_crash():
    @registry.control(id="2.1", title="boom", severity=Severity.HIGH, description="raises")
    def check(host):  # noqa: ARG001
        raise RuntimeError("kaboom")

    report = engine.run(FakeHost(), checks=registry.all_checks())
    result = report.results[0]
    assert result.status is Status.ERROR
    assert "kaboom" in result.finding.detail
    # ERROR is excluded from scoring, so an empty-but-errored run scores 0/0.
    assert result.status not in {Status.PASS, Status.FAIL}


def test_duplicate_control_id_is_rejected():
    _register("3.1")
    with pytest.raises(ValueError, match="duplicate control id"):
        _register("3.1")


def test_results_sorted_numerically_by_id():
    for cid in ["5.2.10", "5.2.2", "5.2.1"]:
        _register(cid)
    ids = [c.control.id for c in registry.all_checks()]
    assert ids == ["5.2.1", "5.2.2", "5.2.10"]


def test_score_counts_only_pass_and_fail():
    _register("1.1")  # pass

    @registry.control(id="1.2", title="skip", severity=Severity.LOW, description="n/a")
    def skip_check(host):  # noqa: ARG001
        return Finding.skipped(detail="not installed")

    report = engine.run(FakeHost(), checks=registry.all_checks())
    assert report.total == 1  # SKIP excluded
    assert report.score == 100
