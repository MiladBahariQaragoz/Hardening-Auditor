"""Markdown report — the hand-off deliverable.

Produces a self-contained `.md`: headline score, a per-severity summary table, the findings
grouped by severity, and a remediation checklist for everything that failed. Deterministic
(stable ordering) so re-running an unchanged host yields a clean diff.
"""

from __future__ import annotations

from ..models import AuditReport, CheckResult, Status
from ._common import grouped, status_counts

_ICON = {
    Status.PASS: "✅",
    Status.FAIL: "❌",
    Status.ERROR: "⚠️",
    Status.SKIP: "➖",
}


def render(report: AuditReport) -> str:
    lines: list[str] = []
    lines.append(f"# Linux Hardening Audit — {report.host}")
    lines.append("")
    lines.append(f"- **Date:** {report.timestamp}")
    lines.append(f"- **Score:** {report.score}%  ({report.passed} / {report.total} controls passing)")
    lines.append("")

    lines += _summary_table(report)
    lines += _findings(report)
    lines += _remediation(report)

    return "\n".join(lines).rstrip() + "\n"


def _summary_table(report: AuditReport) -> list[str]:
    out = ["## Summary by severity", "", "| Severity | Pass | Fail | Error | Skip |", "|---|---|---|---|---|"]
    for severity, members in grouped(report):
        c = status_counts(members)
        out.append(
            f"| {severity.value.title()} | {c[Status.PASS]} | {c[Status.FAIL]} "
            f"| {c[Status.ERROR]} | {c[Status.SKIP]} |"
        )
    out.append("")
    return out


def _findings(report: AuditReport) -> list[str]:
    out = ["## Findings", ""]
    for severity, members in grouped(report):
        out.append(f"### {severity.value.upper()}")
        out.append("")
        out.append("| Status | CIS ID | Control | Found | Expected |")
        out.append("|---|---|---|---|---|")
        for r in members:
            f = r.finding
            out.append(
                f"| {_ICON[r.status]} {r.status.value} | `{r.control.id}` | {r.control.title} "
                f"| {_cell(f.found or f.detail)} | {_cell(f.expected)} |"
            )
        out.append("")
    return out


def _remediation(report: AuditReport) -> list[str]:
    failures = [r for r in report.results if r.status is Status.FAIL]
    if not failures:
        return ["## Remediation", "", "Nothing to remediate — all scored controls pass. 🎉", ""]
    out = ["## Remediation", ""]
    for r in failures:
        out.append(f"- **{r.control.id} — {r.control.title}**  ")
        out.append(f"  {r.control.remediation or '(no remediation recorded)'}")
    out.append("")
    return out


def _cell(text: str) -> str:
    """Escape pipes so free-text never breaks a Markdown table cell."""
    return text.replace("|", "\\|") if text else "—"
