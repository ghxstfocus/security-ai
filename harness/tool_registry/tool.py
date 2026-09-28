"""
Tool-Definition für die Tool Registry.

Jedes Tool hat:
- einen Namen
- ein Permission-Level (0-5)
- ein Sandbox-Profil
- eine Funktion
- erlaubte Argumente
- eine Version

Kein Tool ohne Level. Kein Tool ohne Sandbox (außer Level 5).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from collections.abc import Callable

from harness.permissions.levels import Level


class ToolError(Exception):
    """Basis-Exception für Tool-Fehler."""


class ToolValidationError(ToolError):
    """Tool-Definition ist ungültig."""


class ToolArgumentError(ToolError):
    """Tool wurde mit ungültigen Argumenten aufgerufen."""


# Erlaubte Sandbox-Profile (müssen als Datei in harness/sandbox/profiles/
# existieren). None ist nur für Level 5 erlaubt.
KNOWN_SANDBOX_PROFILES = frozenset({
    "read_only",
    "no_network_except_telegram",
    "nmap_local",
    "local_filesystem",
})

# Regex für Tool-Namen: nur Kleinbuchstaben, Ziffern, Unterstriche
import re

_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")


@dataclass(frozen=True)
class Tool:
    """
    Definition eines Tools.

    Unveränderlich. Wird in der ToolRegistry registriert.
    """
    name: str
    level: Level
    func: Callable[..., Any]
    description: str
    version: str = "1.0.0"
    sandbox_profile: str | None = None
    allowed_args: frozenset[str] = field(default_factory=frozenset)
    returns: str = "any"

    def __post_init__(self) -> None:
        # Name prüfen
        if not _TOOL_NAME_RE.match(self.name):
            raise ToolValidationError(
                f"Ungültiger Tool-Name: '{self.name}'. "
                f"Erlaubt: ^[a-z][a-z0-9_]{{2,63}}$"
            )

        # Level prüfen
        if not isinstance(self.level, Level):
            raise ToolValidationError(
                f"Tool '{self.name}': level muss ein Level sein, "
                f"nicht {type(self.level).__name__}"
            )

        # Funktion prüfen
        if not callable(self.func):
            raise ToolValidationError(
                f"Tool '{self.name}': func muss aufrufbar sein"
            )

        # Sandbox-Regel:
        # - Level 5 (FORBIDDEN): keine Sandbox nötig (wird eh nie ausgeführt)
        # - Alle anderen: Sandbox-Profil Pflicht, und es muss bekannt sein
        if not self.level.is_forbidden:
            if not self.sandbox_profile:
                raise ToolValidationError(
                    f"Tool '{self.name}' (Level {int(self.level)}): "
                    f"sandbox_profile ist Pflicht."
                )
            if self.sandbox_profile not in KNOWN_SANDBOX_PROFILES:
                raise ToolValidationError(
                    f"Tool '{self.name}': unbekanntes Sandbox-Profil "
                    f"'{self.sandbox_profile}'. "
                    f"Erlaubt: {sorted(KNOWN_SANDBOX_PROFILES)}"
                )
        else:
            if self.sandbox_profile is not None:
                raise ToolValidationError(
                    f"Tool '{self.name}': Level 5 darf kein Sandbox-Profil haben."
                )

    def validate_args(self, args: dict[str, Any]) -> None:
        """
        Prüft, dass nur erlaubte Argumente übergeben werden.

        Wirft ToolArgumentError bei unbekannten Argumenten.
        """
        if not self.allowed_args:
            # Kein Argument erlaubt
            if args:
                raise ToolArgumentError(
                    f"Tool '{self.name}' erlaubt keine Argumente, "
                    f"bekam aber: {sorted(args.keys())}"
                )
            return

        unknown = set(args.keys()) - self.allowed_args
        if unknown:
            raise ToolArgumentError(
                f"Tool '{self.name}' bekam unbekannte Argumente: "
                f"{sorted(unknown)}. Erlaubt: {sorted(self.allowed_args)}"
            )

    def __str__(self) -> str:  # pragma: no cover
        return f"Tool({self.name}, level={int(self.level)}, v{self.version})"


__all__ = [
    "KNOWN_SANDBOX_PROFILES",
    "Tool",
    "ToolArgumentError",
    "ToolError",
    "ToolValidationError",
]
