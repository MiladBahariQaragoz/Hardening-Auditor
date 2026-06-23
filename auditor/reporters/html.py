"""Self-contained HTML report — a presentable artifact to open in a browser or attach.

One file, inline CSS, no external assets or JS. Colour-coded by status, grouped by severity.
All dynamic text is HTML-escaped.
"""

from __future__ import annotations

from html import escape

from ..models import AuditReport, CheckResult, Status
from ._common import grouped

_BADGE = {
    Status.PASS: ("PASS", "#1a7f37"),
    Status.FAIL: ("FAIL", "#cf222e"),
    Status.ERROR: ("ERROR", "#9a6700"),
    Status.SKIP: ("SKIP", "#57606a"),
}

_CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
       margin: 2rem auto; max-width: 960px; color: #1f2328; }
h1 { margin-bottom: .25rem; }
.meta { color: #57606a; margin-bottom: 1.5rem; }
.score { font-size: 2rem; font-weight: 700; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }
th, td { border: 1px solid #d0d7de; padding: .5rem .6rem; text-align: left; vertical-align: top; }
th { background: #f6f8fa; }
.badge { color: #fff; padding: .1rem .5rem; border-radius: 1rem; font-size: .8rem; font-weight: 600; }
code { background: #eff1f3; padding: .1rem .3rem; border-radius: 4px; }
h2 { border-bottom: 1px solid #d0d7de; padding-bottom: .3rem; margin-top: 2rem; }
""".strip()


def render(report: AuditReport) -> str:
    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f"<title>Linux Hardening Audit — {escape(report.host)}</title>",
        f"<style>{_CSS}</style></head><body>",
        f"<h1>Linux Hardening Audit — {escape(report.host)}</h1>",
        f'<p class="meta">{escape(report.timestamp)}</p>',
        f'<p class="score">{report.score}%</p>',
        f"<p>{report.passed} / {report.total} controls passing</p>",
    ]

    for severity, members in grouped(report):
        parts.append(f"<h2>{escape(severity.value.upper())}</h2>")
        parts.append("<table><thead><tr><th>Status</th><th>CIS ID</th><th>Control</th>"
                     "<th>Found</th><th>Expected</th></tr></thead><tbody>")
        parts.extend(_row(r) for r in members)
        parts.append("</tbody></table>")

    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


def _row(r: CheckResult) -> str:
    label, colour = _BADGE[r.status]
    badge = f'<span class="badge" style="background:{colour}">{label}</span>'
    f = r.finding
    found = escape(f.found or f.detail) or "—"
    expected = escape(f.expected) or "—"
    return (
        f"<tr><td>{badge}</td><td><code>{escape(r.control.id)}</code></td>"
        f"<td>{escape(r.control.title)}</td><td>{found}</td><td>{expected}</td></tr>"
    )
