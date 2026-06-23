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
