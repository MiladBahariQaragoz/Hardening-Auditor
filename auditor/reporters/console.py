"""Human-readable terminal summary, grouped by severity (most important first)."""

from __future__ import annotations

from ..models import AuditReport, CheckResult, Status
from ._common import grouped

# Fixed-width tags so columns line up regardless of status.
_TAG = {
    Status.PASS: "PASS",
    Status.FAIL: "FAIL",
    Status.ERROR: "ERR ",
    Status.SKIP: "SKIP",
}


def render(report: AuditReport) -> str:
    lines: list[str] = []
    lines.append(f"Linux Hardening Audit — {report.host} — {report.timestamp}")
    lines.append(f"Score: {report.score}%  ({report.passed} / {report.total} controls passing)")

    for severity, members in grouped(report):
        lines.append("")
        lines.append(severity.value.upper())
        lines.extend(_format_line(r) for r in members)

    return "\n".join(lines) + "\n"


def _format_line(r: CheckResult) -> str:
    line = f"  [{_TAG[r.status]}] {r.control.id:<8} {r.control.title}"
    detail = _evidence(r)
    if detail:
        line += f"    {detail}"
    return line


def _evidence(r: CheckResult) -> str:
    f = r.finding
    if r.status is Status.FAIL and (f.found or f.expected):
        return f'found "{f.found}", expected "{f.expected}"'
    if r.status in (Status.ERROR, Status.SKIP) and f.detail:
        return f.detail
    return ""
