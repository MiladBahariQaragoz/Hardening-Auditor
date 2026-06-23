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
| 11 | 5.2.1 | Permissions on `/etc/ssh/sshd_config` ≤ 0600 | `ssh_sshd_config_perms.py` | medium | implemented+fix |
| 12 | 5.2.5 | SSH `LogLevel` INFO/VERBOSE | `ssh_loglevel.py` | medium | implemented+fix |
| 13 | 5.2.6 | SSH `UsePAM yes` | `ssh_use_pam.py` | medium | implemented+fix |
| 14 | 5.2.9 | SSH `PermitEmptyPasswords no` | `ssh_permit_empty_passwords.py` | high | implemented+fix |
| 15 | 5.2.11 | SSH `IgnoreRhosts yes` | `ssh_ignore_rhosts.py` | medium | implemented+fix |
| 16 | 5.2.12 | SSH `X11Forwarding no` | `ssh_x11_forwarding.py` | medium | implemented+fix |
| 17 | 5.2.14 | SSH strong MAC algorithms | `ssh_macs.py` | medium | implemented+fix |
| 18 | 5.2.15 | SSH strong key-exchange algorithms | `ssh_kex.py` | medium | implemented+fix |
| 19 | 5.2.16 | SSH `AllowTcpForwarding no` | `ssh_allow_tcp_forwarding.py` | medium | implemented+fix |
| 20 | 5.2.18 | SSH `MaxAuthTries` ≤ 4 | `ssh_max_auth_tries.py` | medium | implemented+fix |
| 21 | 5.2.21 | SSH `LoginGraceTime` ≤ 60s | `ssh_login_grace_time.py` | medium | implemented+fix |
| 22 | 6.1.1 | Permissions on `/etc/passwd` ≤ 0644 | `passwd_perms.py` | medium | implemented+fix |
| 23 | 6.1.3 | Permissions on `/etc/group` ≤ 0644 | `group_perms.py` | medium | implemented+fix |
| 24 | 6.1.7 | Permissions on `/etc/gshadow` ≤ 0640 | `gshadow_perms.py` | high | implemented+fix |
| 25 | 5.5.1.1 | Password expiration ≤ 365 days | `pass_max_days.py` | medium | implemented+fix |
| 26 | 5.5.1.2 | Min days between password changes ≥ 1 | `pass_min_days.py` | medium | implemented+fix |
| 27 | 5.5.1.3 | Password expiry warning ≥ 7 days | `pass_warn_age.py` | low | implemented+fix |
| 28 | 1.5.1 | ASLR enabled (`randomize_va_space=2`) | `aslr.py` | medium | implemented+fix |
| 29 | 1.5.4 | Core dumps restricted (`suid_dumpable=0`) | `core_dumps.py` | medium | implemented+fix |
| 30 | 5.1.1 | cron daemon enabled and active | `cron_enabled.py` | low | implemented+fix |
| 31 | 5.1.2 | Permissions on `/etc/crontab` ≤ 0600 | `crontab_perms.py` | medium | implemented+fix |
| 32 | 1.3.1 | AppArmor enabled | `apparmor_enabled.py` | medium | implemented |

> **Benchmark:** CIS Ubuntu Linux 22.04 LTS Benchmark **v1.0.0** (each module's docstring
> records its exact control id). Sub-numbering differs in later benchmark versions (v2.0.0
> moved SSH to §5.1), so the version is pinned deliberately.
>
> † Control 2 is a **hardening best-practice beyond CIS** — disabling password auth is not a
> discrete CIS v1.0.0 control (CIS allows password+MFA); it aligns with BSI IT-Grundschutz
> SYS.1.3 (key-based auth). Controls 9 and 10 are **composite** checks over a section (`§2.2`,
> `§3.3`); the constituent sub-ids are listed in their module docstrings.
>
> **32 controls implemented** (31 with safe remediation; AppArmor is audit-only — enabling it
> needs a reboot). Keep ordering by the `#` column stable so report diffs stay meaningful. The
> full rationale for each control lives in `docs/THREAT-MODEL.md`.
