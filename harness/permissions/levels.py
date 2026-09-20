"""
Permission-Level — Level 0 bis 5.

Jedes Tool hat genau ein Level. Was nicht explizit erlaubt ist,
ist verboten. Fail closed.

Level-Bedeutung:

    Level 0: READ / LOW RISK       — read_logs, get_devices
    Level 1: SECURITY ACTION       — nmap (authorized), telegram_alert
    Level 2: REVIEW REQUIRED       — groesserer Scan, Datenexport
    Level 3: CHANGE REQUIRED       — Konfigurationsvorschlag
    Level 4: APPROVAL REQUIRED     — Firewall-Aenderung, Blocken
    Level 5: FORBIDDEN             — Guardrails aendern, Shell
"""
from __future__ import annotations

from enum import IntEnum


class Level(IntEnum):
    """Berechtigungs-Level für Tools."""
    READ = 0
    SECURITY_ACTION = 1
    REVIEW_REQUIRED = 2
    CHANGE_REQUIRED = 3
    APPROVAL_REQUIRED = 4
    FORBIDDEN = 5

    @property
    def human_in_the_loop(self) -> str:
        """Gibt die Human-in-the-Loop-Kategorie zurück."""
        if self.value <= 1:
            return "AUTOMATIC"
        if self.value <= 3:
            return "REVIEW"
        if self.value == 4:
            return "APPROVAL"
        return "FORBIDDEN"

    @property
    def is_automatic(self) -> bool:
        return self.value <= 1

    @property
    def is_forbidden(self) -> bool:
        return self.value == 5

    @property
    def requires_approval(self) -> bool:
        return self.value == 4

    def __str__(self) -> str:  # pragma: no cover
        return f"Level.{self.name}({self.value})"


class PermissionError(Exception):
    """Wird geworfen, wenn ein Tool-Aufruf nicht erlaubt ist."""


class ForbiddenActionError(PermissionError):
    """Level 5 — immer blockiert."""


def check_level(level: Level, *, context: str = "") -> Level:
    """
    Prüft ein Level und wirft bei Level 5 eine Exception.

    Wird vom Agent Loop aufgerufen, bevor ein Tool ausgeführt wird.

    Rückgabe: das Level, wenn erlaubt.
    Wirft: ForbiddenActionError bei Level 5.
    """
    if not isinstance(level, Level):
        raise PermissionError(f"Ungültiges Level: {level!r}")
    if level.is_forbidden:
        raise ForbiddenActionError(
            f"Aktion ist verboten (Level 5).{(' Kontext: ' + context) if context else ''}"
        )
    return level


__all__ = [
    "Level",
    "PermissionError",
    "ForbiddenActionError",
    "check_level",
]
