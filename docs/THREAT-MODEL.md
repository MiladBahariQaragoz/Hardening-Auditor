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

> Extend this file in lockstep with `docs/CONTROLS.md`. Each new control gets a short,
> attacker-framed paragraph here.
