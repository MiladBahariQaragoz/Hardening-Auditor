"""Human-readable terminal summary, grouped by severity (most important first)."""

from __future__ import annotations

from ..models import AuditReport, CheckResult, Severity, Status
from ..registry import id_sort_key

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

    for severity in Severity:  # HIGH, MEDIUM, LOW — enum declaration order
        group = [r for r in report.results if r.control.severity is severity]
        if not group:
            continue
        group.sort(key=lambda r: id_sort_key(r.control.id))
        lines.append("")
        lines.append(severity.value.upper())
        for r in group:
            lines.append(_format_line(r))

    return "\n".join(lines) + "\n"


def _format_line(r: CheckResult) -> str:
    tag = _TAG[r.status]
    line = f"  [{tag}] {r.control.id:<8} {r.control.title}"
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
