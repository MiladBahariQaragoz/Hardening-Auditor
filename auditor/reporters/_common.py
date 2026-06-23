"""Shared helpers for reporters: deterministic grouping and per-severity tallies.

Underscore-prefixed so the reporter registry never mistakes it for a format. Keeping the
ordering logic in one place is what guarantees every format groups and sorts identically.
"""

from __future__ import annotations

from collections import Counter

from ..models import AuditReport, CheckResult, Severity, Status
from ..registry import id_sort_key


def grouped(report: AuditReport) -> list[tuple[Severity, list[CheckResult]]]:
    """Results grouped by severity (HIGH→LOW) and sorted by CIS id within each group.

    Empty severities are omitted so a report never shows a heading with nothing under it.
    """
    out: list[tuple[Severity, list[CheckResult]]] = []
    for severity in Severity:  # enum declaration order = HIGH, MEDIUM, LOW
        members = sorted(
            (r for r in report.results if r.control.severity is severity),
            key=lambda r: id_sort_key(r.control.id),
        )
        if members:
            out.append((severity, members))
    return out


def status_counts(results: list[CheckResult]) -> Counter[Status]:
    """Tally of each ``Status`` across the given results."""
    return Counter(r.status for r in results)
