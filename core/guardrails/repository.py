"""Guardrail-Repository (Phase 5).

Persistenz-Schicht fuer Guardrails. Liest und schreibt
die Tabelle guardrails in SQLite.

Modell-Mapping (U4-22-A1): Das Modell Guardrail hat
vier Felder (id, name, level, state). Die Migration
hat sechs Spalten. created_at und updated_at sind
Infrastruktur-Spalten und werden NICHT ins Modell
gemappt. Alle SELECTs lesen nur die vier Modell-Spalten.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from core.guardrails.models import Guardrail, GuardrailLevel, GuardrailState


class GuardrailRepositoryError(Exception):
    """Basis-Fehler der Repository-Schicht."""


class GuardrailNotFoundError(GuardrailRepositoryError):
    """Die angeforderte id existiert nicht."""


class GuardrailRepository:
    """Repository fuer Guardrails."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    def list_all(self) -> list[Guardrail]:
        """Alle Guardrails, sortiert nach id."""
        conn = sqlite3.connect(self._db_path)
        try:
            cur = conn.execute(
                "SELECT id, name, level, state FROM guardrails ORDER BY id"
            )
            rows = cur.fetchall()
        finally:
            conn.close()
        return [
            Guardrail(
                id=row[0],
                name=row[1],
                level=GuardrailLevel(row[2]),
                state=GuardrailState(row[3]),
            )
            for row in rows
        ]

    def get(self, id: str) -> Guardrail:
        """Einzelner Guardrail. Wirft GuardrailNotFoundError."""
        conn = sqlite3.connect(self._db_path)
        try:
            cur = conn.execute(
                "SELECT id, name, level, state FROM guardrails WHERE id = ?",
                (id,),
            )
            row = cur.fetchone()
        finally:
            conn.close()
        if row is None:
            raise GuardrailNotFoundError(id)
        return Guardrail(
            id=row[0],
            name=row[1],
            level=GuardrailLevel(row[2]),
            state=GuardrailState(row[3]),
        )

    def set_state(self, id: str, state: str) -> None:
        """Setzt den Zustand eines Guardrails.

        Reihenfolge (U4-Praez-A5):
          1. GuardrailState(state) validiert den Wert.
             ValueError propagiert (Programmierfehler).
          2. UPDATE mit updated_at.
          3. rowcount == 0 -> GuardrailNotFoundError.
        """
        GuardrailState(state)
        updated_at = datetime.now(UTC).isoformat()
        conn = sqlite3.connect(self._db_path)
        try:
            cur = conn.execute(
                "UPDATE guardrails SET state = ?, updated_at = ? WHERE id = ?",
                (state, updated_at, id),
            )
            conn.commit()
            rowcount = cur.rowcount
        finally:
            conn.close()
        if rowcount == 0:
            raise GuardrailNotFoundError(id)