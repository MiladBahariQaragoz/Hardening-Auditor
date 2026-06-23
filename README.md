# 01 — Linux Hardening Lab & CIS Auto-Auditor

**Difficulty:** ⭐ (start here) · **Est. effort:** 2–3 weeks · **Repo name idea:** `linux-cis-auditor`

## Why this project
Every junior security CV needs to prove you understand *what a secure system looks like* and
can *measure deviation from a baseline*. 30% of the analysed jobs ask for "IT security"
fundamentals and 12% for "security audits" / "system hardening". This is the cheapest, fastest
way to make those skills real — and it plays to your Python/Bash automation strength.

## Skills this proves (put on CV)
- IT security fundamentals & **system hardening**
- **Security auditing** against a recognised benchmark (CIS / BSI Grundschutz)
- Linux administration & secure configuration
- Security **automation** in Python/Bash

## Scope / what you build
A tool that audits a Linux host against the **CIS Benchmark** (or BSI IT-Grundschutz),
reports pass/fail per control, and can optionally **remediate**.

1. **Lab:** 2 VMs (Ubuntu + Debian) in VirtualBox/UTM, one left default, one hardened.
2. **Auditor (Python):** checks 30–50 real controls — SSH config (`PermitRootLogin`, key-only
   auth), password policy, `auditd` enabled, firewall (ufw/nftables) on, unattended-upgrades,
   file permissions on `/etc/shadow`, disabled unused services, kernel `sysctl` hardening.
3. **Report:** generates a clean Markdown/HTML report with score, severity, and remediation
   steps per failed control — this is the "audit deliverable" recruiters can see.
4. **Remediation mode:** `--fix` applies safe fixes idempotently (with backup + dry-run).
5. **Bonus:** compare your auditor's output against **Lynis** and **OpenSCAP** and document
   the diff (shows you know the industry-standard tools, not just your own).

## Definition of done
- [ ] Public repo with README showing a before/after audit score (e.g. 41% → 92%).
- [ ] Screenshots of the hardened-vs-default report.
- [ ] At least 30 controls implemented, mapped to CIS control IDs.
- [ ] `--dry-run`, `--fix`, and Markdown report output all work.
- [ ] A short "Threat model & rationale" section: *why* each control matters.

## Build order
1. Stand up the two VMs; snapshot them.
2. Run **Lynis** manually first — learn the vocabulary, note ~20 findings.
3. Re-implement 30+ of those checks in your own auditor.
4. Add the reporting layer, then the remediation layer.
5. Document the CIS mapping + your audit methodology.

## Learning resources
- CIS Benchmarks (free PDF after sign-up), BSI IT-Grundschutz Kompendium (German, CV-relevant).
- `Lynis`, `OpenSCAP`/`oscap`, `auditd` docs.
- TryHackMe "Linux Fundamentals" + "Hardening" rooms.

## CV bullet (target)
> Built an open-source Linux hardening auditor that scores hosts against 40+ CIS controls and
> auto-remediates findings; reduced a default Ubuntu image's audit failures by ~80%.
