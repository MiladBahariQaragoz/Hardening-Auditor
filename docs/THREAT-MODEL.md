# Threat Model & Rationale

*Why* each control exists — the attacker behaviour it frustrates. This is the section
recruiters read to see you understand security, not just tooling. Add a rationale entry the
moment a control is established in `docs/CONTROLS.md` (same commit).

## Assets & adversary
- **Assets:** confidentiality/integrity of the host, its credentials (`/etc/shadow`), its
  audit trail, and continued availability of services.
- **Adversary:** a remote, unauthenticated attacker probing exposed services, plus a
  post-compromise attacker trying to escalate privilege, persist, and cover tracks.
- **Goal of hardening:** raise the cost of each attacker step and ensure their actions are
  detectable.

## Per-control rationale

### SSH `PermitRootLogin no` (high)
Direct root login over SSH lets an attacker brute-force the single most valuable account and
removes the audit gap between "who logged in" and "who became root". Forcing login as an
unprivileged user + `sudo` gives attribution and a second factor of access.

### SSH key-only auth — `PasswordAuthentication no` (high)
Passwords are guessable and reused; SSH is the most-attacked service on the public internet.
Key-only auth makes online brute force infeasible.

### `auditd` enabled (high)
Without a kernel audit trail, a post-compromise attacker operates blind to defenders — no
record of privilege escalation, file tampering, or persistence. `auditd` is the detection
backbone the other controls assume exists.

### Host firewall active (high)
Default-deny inbound shrinks the attack surface to only the services you intend to expose,
neutralising forgotten/listening daemons.

### `/etc/shadow` permissions (high)
World/group-readable password hashes hand an attacker offline cracking material — turning a
low-priv foothold into full credential compromise.

### SSH strong ciphers only (medium)
CBC-mode and RC4/arcfour ciphers have practical weaknesses (padding-oracle, keystream biases).
A network-positioned attacker who can force a weak cipher can tamper with or recover session
data. Offering only AEAD/CTR ciphers removes that downgrade path.

### Password minimum length ≥ 14 (medium)
Short passwords fall in minutes to offline cracking once a hash leaks (see `/etc/shadow`). A
14-character floor multiplies the keyspace an attacker must search, buying time to detect and
rotate after a breach.

### Automatic security updates (medium)
The majority of real-world compromises exploit *known, already-patched* CVEs. Unattended
security upgrades shrink the exposure window between a fix shipping and an operator applying it
— the window attackers race to exploit after a disclosure.

### No unnecessary legacy services (medium)
Every listening daemon is attack surface, and cleartext legacy protocols (telnet, rsh, tftp)
additionally leak credentials on the wire. Not running what you don't need removes whole
classes of vulnerability you'd otherwise have to monitor and patch.

### Kernel `sysctl` network hardening (medium)
Defaults permit IP forwarding, ICMP/source-route redirects, and acceptance of redirects that a
normal host never needs. These are the primitives behind spoofing, on-path traffic redirection,
and MITM. Disabling them (and enabling reverse-path filtering / SYN cookies) denies the attacker
those building blocks.

### SSH session & crypto hardening (5.2.x)
A cluster of sshd settings that each remove an attacker primitive:
- **sshd_config perms 0600 (5.2.1):** a writable config lets a low-priv user re-enable root
  login; a readable one leaks the host's exact auth posture.
- **LogLevel INFO/VERBOSE (5.2.5):** below INFO, the logins and key fingerprints responders
  need simply aren't recorded.
- **UsePAM yes (5.2.6):** without PAM, sshd bypasses account-expiry, access-limit and session
  policy entirely.
- **PermitEmptyPasswords no (5.2.9):** an empty-password account is a remote login with no
  secret at all.
- **IgnoreRhosts yes (5.2.11):** rhosts trust grants login based only on source host — an
  attacker who owns a "trusted" host walks in.
- **X11Forwarding no (5.2.12):** a malicious server can sniff keystrokes from a forwarded X
  session.
- **strong MACs / KEX (5.2.14/5.2.15):** MD5/SHA1 MACs and SHA1/small-group key exchanges let
  an on-path attacker forge integrity or threaten the session key.
- **AllowTcpForwarding no (5.2.16):** forwarding turns SSH into a pivot/exfil tunnel past the
  firewall.
- **MaxAuthTries ≤ 4 (5.2.18) / LoginGraceTime ≤ 60s (5.2.21):** cap online guessing and stop
  an attacker from parking many unauthenticated connections (a cheap DoS and a wider brute window).

### Sensitive file permissions (6.1.x, 5.1.2)
`/etc/passwd` and `/etc/group` writable by non-root means added accounts or self-promotion into
`sudo`; `/etc/gshadow` readable leaks group password hashes (mirrors `/etc/shadow`); a writable
`/etc/crontab` is direct root code execution. Each control pins owner root and a least-permissive
mode.

### Password aging (5.5.1.x)
`PASS_MAX_DAYS ≤ 365` bounds how long a leaked password stays valid; `PASS_MIN_DAYS ≥ 1` stops a
user from immediately cycling back to an old password after a forced change; `PASS_WARN_AGE ≥ 7`
avoids rushed, weak password choices at expiry.

### Process hardening (1.5.x)
**ASLR (1.5.1)** randomizes memory layout so memory-corruption exploits can't rely on fixed
addresses. **Restricting core dumps (1.5.4)** stops a setuid process from spilling in-memory
secrets (keys, hashes) into a file a lesser user can read.

### cron daemon enabled (5.1.1)
Log rotation, integrity scans, and automatic updates run from cron; if it isn't running, those
protections silently stop.

### AppArmor enabled (1.3.1)
Mandatory access control confines each program to what it legitimately needs, so one exploited
daemon can't roam the whole system. Audit-only here — enabling it safely requires a reboot.

> Extend this file in lockstep with `docs/CONTROLS.md`. Each new control gets a short,
> attacker-framed paragraph here.
