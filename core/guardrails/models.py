"""Guardrail-Modell (Phase 5).

Reines Datenmodell. Keine Persistenz, keine Logik.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class GuardrailLevel(str, Enum):
    """Schweregrad eines Guardrails."""

    INFO = "info"
    WARN = "warn"
    BLOCK = "block"


class GuardrailState(str, Enum):
    """Aktivierungszustand eines Guardrails."""

    ENABLED = "enabled"
    DISABLED = "disabled"


@dataclass(frozen=True)
class Guardrail:
    """Ein Guardrail.

    Genau vier Felder. Keine weiteren.
    """

    id: str
    name: str
    level: GuardrailLevel
    state: GuardrailState