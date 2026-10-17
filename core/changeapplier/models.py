"""Datenmodelle fuer den ChangeApplier.

Enthaelt nur Datenklassen und die Zustandspruefung.
Keine Datei-IO in diesem Modul.

Fail-closed: Ein ungueltiger Zustandsuebergang wirft
ValueError.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class ChangeState(Enum):
    """Zustand eines Changes."""

    PENDING = "pending"
    APPLIED = "applied"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


# Erlaubte Zustandsuebergaenge.
# PENDING -> APPLIED, PENDING -> FAILED
# APPLIED -> ROLLED_BACK
# FAILED  -> (kein weiterer Uebergang)
# ROLLED_BACK -> (kein weiterer Uebergang)
_ALLOWED_TRANSITIONS: dict[ChangeState, frozenset[ChangeState]] = {
    ChangeState.PENDING: frozenset(
        {ChangeState.APPLIED, ChangeState.FAILED}
    ),
    ChangeState.APPLIED: frozenset({ChangeState.ROLLED_BACK}),
    ChangeState.ROLLED_BACK: frozenset(),
    ChangeState.FAILED: frozenset(),
}


@dataclass
class Change:
    """Ein anzuwendender Change mit Zustandsmaschine."""

    id: str
    target: str
    payload: dict = field(default_factory=dict)
    state: ChangeState = ChangeState.PENDING
    applied_at: datetime | None = None

    def transition_to(self, new_state: ChangeState) -> None:
        """Setzt den Zustand, sofern der Uebergang erlaubt ist.

        Fail-closed: ungueltiger Uebergang wirft ValueError.
        """
        allowed = _ALLOWED_TRANSITIONS.get(self.state, frozenset())
        if new_state not in allowed:
            raise ValueError(
                f"Ungueltiger Zustandsuebergang: "
                f"{self.state.value} -> {new_state.value}"
            )
        self.state = new_state


class ChangeApplier:
    """Wendet Changes auf eine Konfigurationsdatei an.

    Grundgeruest: keine Logik in dieser Runde.
    """

    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path

    def apply(self, change: Change) -> None:
        """Wendet einen Change an. Grundgeruest, keine Logik."""
        raise NotImplementedError("ChangeApplier.apply ist noch nicht implementiert")

    def rollback(self, change: Change) -> None:
        """Rollt einen Change zurueck. Grundgeruest, keine Logik."""
        raise NotImplementedError(
            "ChangeApplier.rollback ist noch nicht implementiert"
        )