"""Machine-readable JSON output, for diffing runs or feeding other tools.

Keys are stable and results are ordered by CIS id so two runs of an unchanged host produce
byte-identical output (modulo the timestamp) — meaningful diffs are a debuggability goal.
"""

from __future__ import annotations

import json as _json

from ..models import AuditReport, CheckResult
from ..registry import id_sort_key


def render(report: AuditReport) -> str:
    payload = {
        "host": report.host,
        "timestamp": report.timestamp,
        "score": report.score,
        "passed": report.passed,
        "total": report.total,
        "results": [_result(r) for r in sorted(report.results, key=lambda r: id_sort_key(r.control.id))],
    }
    return _json.dumps(payload, indent=2, sort_keys=False) + "\n"


def _result(r: CheckResult) -> dict:
    c, f = r.control, r.finding
    return {
        "id": c.id,
        "title": c.title,
        "severity": c.severity.value,
        "status": r.status.value,
        "found": f.found,
        "expected": f.expected,
        "detail": f.detail,
        "remediation": c.remediation,
        "benchmark": c.benchmark,
    }
