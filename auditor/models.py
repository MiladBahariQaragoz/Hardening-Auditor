"""Core domain types shared by the engine, checks, and reporters.

These dataclasses are the contract between the three layers. Checks produce a ``Finding``;
the engine pairs it with the ``Control`` it ran into a ``CheckResult``; reporters render
``CheckResult`` objects. Nothing here knows about any specific control or output format.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """How much a failing control matters. Drives report ordering and score weight."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """Sort key: HIGH sorts before MEDIUM before LOW (most important first)."""
        return {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}[self]


class Status(Enum):
    """Outcome of running a single check against a host."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"  # the check itself blew up — never silently swallowed
    SKIP = "skip"    # not applicable to this host (e.g. service not installed)


@dataclass(frozen=True)
class Control:
    """Static metadata for one hardening control, mapped to a real benchmark ID.

    A ``Control`` is declared once, next to its check, via the ``@control(...)`` decorator
    in ``auditor.registry``. The ``id`` flows unbroken from ``docs/CONTROLS.md`` → here →
    the report line, which is what makes findings traceable (ADR-0003).
    """

    id: str            # CIS Benchmark control id, e.g. "5.2.8"
    title: str         # short human label, e.g. "SSH PermitRootLogin no"
    severity: Severity
    description: str   # what the check verifies, one line
    rationale: str = ""      # short attacker-framed "why" (mirrors docs/THREAT-MODEL.md)
    remediation: str = ""    # how to fix it manually
    benchmark: str = ""      # exact benchmark + version this id comes from


@dataclass(frozen=True)
class Finding:
    """What a check returns: the verdict plus the evidence behind it.

    ``expected`` / ``found`` are the heart of debuggability — every failure says what it
    wanted vs. what it saw, in the report, with no need to re-run by hand.
    """

    status: Status
    found: str = ""
    expected: str = ""
    detail: str = ""

    @classmethod
    def passed(cls, *, found: str = "", expected: str = "", detail: str = "") -> Finding:
        return cls(Status.PASS, found=found, expected=expected, detail=detail)

    @classmethod
    def failed(cls, *, found: str = "", expected: str = "", detail: str = "") -> Finding:
        return cls(Status.FAIL, found=found, expected=expected, detail=detail)

    @classmethod
    def skipped(cls, *, detail: str = "") -> Finding:
        return cls(Status.SKIP, detail=detail)


@dataclass(frozen=True)
class CheckResult:
    """A ``Finding`` bound to the ``Control`` that produced it — the unit reporters render."""

    control: Control
    finding: Finding

    @property
    def status(self) -> Status:
        return self.finding.status

    @property
    def is_pass(self) -> bool:
        return self.finding.status is Status.PASS


@dataclass
class AuditReport:
    """A whole run: the host, when it ran, and every result. Reporters consume this."""

    host: str
    timestamp: str  # ISO-8601; injectable so report tests stay deterministic
    results: list[CheckResult] = field(default_factory=list)

    @property
    def scored(self) -> list[CheckResult]:
        """Results that count toward the score (PASS/FAIL); SKIP/ERROR are excluded."""
        return [r for r in self.results if r.status in (Status.PASS, Status.FAIL)]

    @property
    def passed(self) -> int:
        return sum(1 for r in self.scored if r.status is Status.PASS)

    @property
    def total(self) -> int:
        return len(self.scored)

    @property
    def score(self) -> int:
        """Percentage of scored controls that pass (0 when nothing is scorable)."""
        return round(100 * self.passed / self.total) if self.total else 0
