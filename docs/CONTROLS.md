# Control Catalogue

The single source of truth for which controls exist, their benchmark mapping, severity, and
implementation status. **Every** added/changed/removed control updates this table in the same
commit as the code. Target for "done": 30+ implemented controls (see `README.md`).

- **Status:** `planned` | `implemented` | `implemented+fix` (audit + safe remediation).
- **Severity:** `high` | `medium` | `low` — drives report ordering and score weight.
- **CIS ID:** control number from the CIS Benchmark for the target distro (record the exact
  benchmark + version in the check module docstring).

| # | CIS ID | Control | Module | Severity | Status |
|---|--------|---------|--------|----------|--------|
| 1 | 5.2.7 | SSH: `PermitRootLogin no` | `ssh_permit_root_login.py` | high | implemented+fix |
| 2 | 5.2 (BP)† | SSH: `PasswordAuthentication no` (key-only) | `ssh_password_auth.py` | high | implemented+fix |
| 3 | 5.2.13 | SSH: only strong ciphers (no CBC/arcfour/3des) | `ssh_ciphers.py` | medium | implemented+fix |
| 4 | 5.4.1 | Password policy: minimum length ≥ 14 | `pwquality.py` | medium | implemented+fix |
| 5 | 4.1.1.2 | `auditd` installed, enabled, and active | `auditd_enabled.py` | high | implemented+fix |
| 6 | 3.5.1.3 | Host firewall active (ufw/nftables) | `firewall_active.py` | high | implemented+fix |
| 7 | 1.9 | Automatic security upgrades enabled | `unattended_upgrades.py` | medium | implemented+fix |
| 8 | 6.1.5 | `/etc/shadow` permissions ≤ `0640` | `shadow_perms.py` | high | implemented+fix |
| 9 | §2.2 | No unnecessary legacy services running | `disabled_services.py` | medium | implemented |
| 10 | §3.3 | Kernel `sysctl` network hardening | `sysctl_network.py` | medium | implemented+fix |

> **Benchmark:** CIS Ubuntu Linux 22.04 LTS Benchmark **v1.0.0** (each module's docstring
> records its exact control id). Sub-numbering differs in later benchmark versions (v2.0.0
> moved SSH to §5.1), so the version is pinned deliberately.
>
> † Control 2 is a **hardening best-practice beyond CIS** — disabling password auth is not a
> discrete CIS v1.0.0 control (CIS allows password+MFA); it aligns with BSI IT-Grundschutz
> SYS.1.3 (key-based auth). Controls 9 and 10 are **composite** checks over a section (`§2.2`,
> `§3.3`); the constituent sub-ids are listed in their module docstrings.
>
> Rows above are the seed set (all 10 implemented). Expand toward 30+ as checks are added; keep
> ordering by the `#` column stable so report diffs stay meaningful. The full rationale for each
> control lives in `docs/THREAT-MODEL.md`.
