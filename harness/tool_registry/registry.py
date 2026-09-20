"""
Tool Registry — zentrale Verwaltung aller Tools.

Regeln:
- Kein Tool ohne Registrierung.
- Kein doppelter Name.
- Kein Tool-Aufruf ohne Validierung.
- Kein stillschweigendes Überschreiben.

Verwendung:

    from harness.tool_registry.registry import ToolRegistry

    registry = ToolRegistry()
    registry.register(tool)
    tool = registry.get("read_logs")
    registry.list_tools()
"""
from __future__ import annotations

import threading
from typing import Iterable

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool, ToolError


class ToolNotFoundError(ToolError):
    """Wird geworfen, wenn ein Tool nicht registriert ist."""


class ToolAlreadyRegisteredError(ToolError):
    """Wird geworfen, wenn ein Tool-Name bereits vergeben ist."""


class ToolRegistry:
    """
    Zentrale Verwaltung aller Tools.

    Thread-safe. Tools werden einmal registriert und danach nur gelesen.
    """

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._lock = threading.Lock()

    def register(self, tool: Tool) -> None:
        """
        Registriert ein Tool.

        Wirft ToolAlreadyRegisteredError, wenn der Name schon vergeben ist.
        Wirft ToolError, wenn tool kein Tool ist.
        """
        if not isinstance(tool, Tool):
            raise ToolError(f"Erwartet Tool, bekam {type(tool).__name__}")

        with self._lock:
            if tool.name in self._tools:
                raise ToolAlreadyRegisteredError(
                    f"Tool '{tool.name}' ist bereits registriert."
                )
            self._tools[tool.name] = tool

    def register_many(self, tools: Iterable[Tool]) -> None:
        """Registriert mehrere Tools. Alles oder nichts."""
        with self._lock:
            # Erst prüfen, ob alle Namen frei sind
            names = [t.name for t in tools]
            if len(names) != len(set(names)):
                duplicates = [n for n in names if names.count(n) > 1]
                raise ToolAlreadyRegisteredError(
                    f"Doppelte Namen in der Liste: {sorted(set(duplicates))}"
                )
            already = [n for n in names if n in self._tools]
            if already:
                raise ToolAlreadyRegisteredError(
                    f"Bereits registriert: {sorted(already)}"
                )
            # Alle registrieren
            for t in tools:
                self._tools[t.name] = t

    def get(self, name: str) -> Tool:
        """
        Gibt ein Tool zurück.

        Wirft ToolNotFoundError, wenn der Name nicht registriert ist.
        """
        with self._lock:
            tool = self._tools.get(name)
        if tool is None:
            raise ToolNotFoundError(
                f"Tool '{name}' ist nicht registriert. "
                f"Registriert sind: {sorted(self._tools.keys())}"
            )
        return tool

    def has(self, name: str) -> bool:
        with self._lock:
            return name in self._tools

    def list_names(self) -> list[str]:
        """Gibt alle registrierten Tool-Namen sortiert zurück."""
        with self._lock:
            return sorted(self._tools.keys())

    def list_tools(self) -> list[Tool]:
        """Gibt alle registrierten Tools sortiert nach Namen zurück."""
        with self._lock:
            return [self._tools[n] for n in sorted(self._tools.keys())]

    def list_by_level(self, level: Level) -> list[Tool]:
        """Gibt alle Tools mit einem bestimmten Level zurück."""
        with self._lock:
            return [
                t for t in self._tools.values() if t.level == level
            ]

    def list_forbidden(self) -> list[Tool]:
        """Gibt alle verbotenen Tools zurück (Level 5)."""
        return self.list_by_level(Level.FORBIDDEN)

    def __len__(self) -> int:
        with self._lock:
            return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return self.has(name)

    def __repr__(self) -> str:  # pragma: no cover
        return f"ToolRegistry({len(self)} Tools)"


__all__ = [
    "ToolRegistry",
    "ToolNotFoundError",
    "ToolAlreadyRegisteredError",
]
