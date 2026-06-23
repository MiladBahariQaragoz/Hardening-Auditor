"""Shared helpers for SSH-related controls.

The leading underscore tells the engine's discovery to skip this module — it declares no
control, it just gives the SSH checks one correct place to read sshd's configuration.

Resolving sshd config correctly is subtle, so it lives here once:

* The authoritative source is ``sshd -T``, which prints the *effective* configuration after
  defaults, ``Include`` files, and ``Match`` blocks are applied. We prefer it.
* When ``sshd -T`` is unavailable (no sshd, not root), we fall back to parsing
  ``/etc/ssh/sshd_config``. Per ``sshd_config(5)`` the **first** value obtained for a keyword
  wins, so the parser keeps the first occurrence — matching sshd's real behaviour.
"""

from __future__ import annotations

from ..host import Host
from ..models import Finding
from ..remediation import Action, RunCommand, WriteFile

SSHD_CONFIG = "/etc/ssh/sshd_config"
SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"


def dropin_actions(filename: str, directives: list[str]) -> list[Action]:
    """Plan to harden sshd via a drop-in under sshd_config.d, then validate and reload.

    Ubuntu's default sshd_config ``Include``s ``sshd_config.d/*.conf`` at the top, so a drop-in
    wins over later settings (sshd uses the first value seen). We always ``sshd -t`` before
    reloading so a bad config can never take down SSH access.
    """
    content = "# Managed by linux-hardening-auditor\n" + "\n".join(directives) + "\n"
    return [
        WriteFile(f"{SSHD_CONFIG_D}/{filename}", content, mode=0o600),
        RunCommand(("sshd", "-t"), "validate sshd configuration before reload"),
        RunCommand(("systemctl", "reload", "ssh"), "apply new sshd configuration"),
    ]


def effective_config(host: Host) -> tuple[dict[str, str] | None, str]:
    """Return sshd's effective config as ``{lowercased_key: value}`` plus its source.

    Returns ``(None, reason)`` when no configuration can be read at all (sshd absent), which
    callers should treat as "not applicable" rather than a failure.
    """
    result = host.run(["sshd", "-T"])
    if result.ok and result.stdout.strip():
        return _parse(result.stdout, first_wins=False), "sshd -T"

    text = host.read_text(SSHD_CONFIG)
    if text is not None:
        return _parse(text, first_wins=True), SSHD_CONFIG

    return None, "sshd not present / config unreadable"


def require_equals(host: Host, key: str, want: str, *, default_note: str = "") -> Finding:
    """Pass iff sshd's effective ``key`` equals ``want`` (case-insensitive)."""
    config, _ = effective_config(host)
    if config is None:
        return Finding.skipped(detail="sshd not present / config unreadable")
    value = config.get(key)
    if value is None:
        found = "unset" + (f" ({default_note})" if default_note else "")
        return Finding.failed(found=found, expected=want)
    if value.lower() == want.lower():
        return Finding.passed(found=value, expected=want)
    return Finding.failed(found=value, expected=want)


def require_in(host: Host, key: str, allowed: tuple[str, ...]) -> Finding:
    """Pass iff sshd's effective ``key`` is one of ``allowed`` (case-insensitive)."""
    config, _ = effective_config(host)
    if config is None:
        return Finding.skipped(detail="sshd not present / config unreadable")
    value = config.get(key)
    want = " or ".join(allowed)
    if value is None:
        return Finding.failed(found="unset", expected=want)
    if value.lower() in {a.lower() for a in allowed}:
        return Finding.passed(found=value, expected=want)
    return Finding.failed(found=value, expected=want)


def require_at_most(host: Host, key: str, limit: int) -> Finding:
    """Pass iff sshd's effective integer ``key`` is <= ``limit``."""
    config, _ = effective_config(host)
    if config is None:
        return Finding.skipped(detail="sshd not present / config unreadable")
    value = config.get(key)
    if value is None:
        return Finding.failed(found="unset", expected=f"<= {limit}")
    try:
        number = int(value.split()[0])  # MaxStartups is "10:30:60"; first field is the count
    except (ValueError, IndexError):
        return Finding.failed(found=value, expected=f"integer <= {limit}")
    if number <= limit:
        return Finding.passed(found=value, expected=f"<= {limit}")
    return Finding.failed(found=value, expected=f"<= {limit}")


def require_no_weak(host: Host, key: str, weak: frozenset[str]) -> Finding:
    """Pass iff none of sshd's effective ``key`` algorithms are in the ``weak`` set."""
    config, _ = effective_config(host)
    if config is None:
        return Finding.skipped(detail="sshd not present / config unreadable")
    raw = config.get(key)
    if raw is None:
        return Finding.failed(found="unset (compiled-in default)", expected="explicit strong list")
    offered = [a.strip().lower() for a in raw.split(",") if a.strip()]
    bad = [a for a in offered if a in weak]
    if bad:
        return Finding.failed(found=", ".join(bad), expected="no weak algorithms")
    return Finding.passed(found=raw, expected="no weak algorithms")


def _parse(text: str, *, first_wins: bool) -> dict[str, str]:
    config: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts[0].lower(), parts[1].strip()
        if first_wins and key in config:
            continue  # sshd_config(5): first obtained value wins
        config[key] = value
    return config
