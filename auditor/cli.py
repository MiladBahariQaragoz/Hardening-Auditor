"""Command-line entrypoint: ``audit`` (read-only) and ``fix`` (remediation, opt-in).

This module wires the pieces together; it contains no control logic. ``audit`` builds a
``LocalHost``, runs the engine, and renders the chosen report. ``fix`` is reserved for the
remediation phase and currently refuses to mutate anything (ADR-0002: read-only by default).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .engine import run
from .host import LocalHost
from .models import Status
from .reporters import available, get_reporter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditor",
        description="Audit a Linux host against the CIS Benchmark.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="diagnostic log verbosity (default: WARNING)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="read-only audit; never modifies the host")
    audit.add_argument(
        "--report",
        default="console",
        choices=available(),
        help="output format (default: console)",
    )
    audit.add_argument(
        "--output",
        type=Path,
        help="write the report to this file instead of stdout",
    )
    audit.set_defaults(func=_cmd_audit)

    fix = sub.add_parser("fix", help="apply safe remediations (opt-in, with backups)")
    fix.add_argument("--dry-run", action="store_true", help="show what would change, change nothing")
    fix.set_defaults(func=_cmd_fix)

    return parser


def _cmd_audit(args: argparse.Namespace) -> int:
    report = run(LocalHost())
    rendered = get_reporter(args.report)(report)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"wrote {args.report} report to {args.output}")
    else:
        sys.stdout.write(rendered)

    # Exit non-zero if any control failed or errored — useful in CI/pipelines.
    bad = {Status.FAIL, Status.ERROR}
    return 1 if any(r.status in bad for r in report.results) else 0


def _cmd_fix(args: argparse.Namespace) -> int:
    print("remediation is not implemented yet (planned for Phase 4); no changes were made.")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Reports contain non-ASCII (e.g. em-dashes); force UTF-8 so a legacy Windows
    # console codepage doesn't mangle them. No-op where stdout is already UTF-8.
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (ValueError, OSError):
            pass

    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s %(name)s: %(message)s",
    )
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
