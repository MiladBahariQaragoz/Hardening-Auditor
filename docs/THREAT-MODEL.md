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

> Extend this file in lockstep with `docs/CONTROLS.md`. Each new control gets a short,
> attacker-framed paragraph here.
