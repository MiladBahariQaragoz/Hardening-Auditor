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
| 1 | 5.2.8 | SSH: `PermitRootLogin no` | `ssh_permit_root_login.py` | high | implemented |
| 2 | 5.2.x | SSH: `PasswordAuthentication no` (key-only) | `ssh_password_auth.py` | high | planned |
| 3 | 5.2.x | SSH: `Protocol 2` / weak ciphers disabled | `ssh_ciphers.py` | medium | planned |
| 4 | 5.4.x | Password policy: min length / complexity | `pwquality.py` | medium | planned |
| 5 | 4.1.x | `auditd` installed and enabled | `auditd_enabled.py` | high | planned |
| 6 | 3.5.x | Host firewall active (ufw/nftables) | `firewall_active.py` | high | planned |
| 7 | 1.x | Unattended security upgrades enabled | `unattended_upgrades.py` | medium | planned |
| 8 | 6.1.x | `/etc/shadow` permissions `0640`/`0000` | `shadow_perms.py` | high | planned |
| 9 | 2.2.x | Unused services disabled | `disabled_services.py` | medium | planned |
| 10 | 3.3.x | Kernel `sysctl` network hardening | `sysctl_network.py` | medium | planned |

> Rows above are the seed set. Expand toward 30+ as checks are implemented; keep ordering by
> the `#` column stable so report diffs stay meaningful. The full rationale for each control
> lives in `docs/THREAT-MODEL.md`.
