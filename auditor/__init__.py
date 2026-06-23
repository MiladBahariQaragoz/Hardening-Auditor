"""Linux Hardening Auditor.

Audits a Linux host against the CIS Benchmark, reporting pass/fail per control with a
severity and remediation, and can optionally apply safe, reversible fixes.

The package is organised so that adding a control never means editing the engine
(see ``docs/DECISIONS.md`` ADR-0001): each control is a self-registering plugin under
``auditor.checks``. Checks never touch the OS directly — they read facts from an injected
``Host`` (ADR-0004), which makes them testable off-Linux and retargetable.
"""

__version__ = "0.1.0"
