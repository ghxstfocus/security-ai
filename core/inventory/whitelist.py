"""
Whitelist-Logik.

Die Whitelist ist eine eigene Tabelle (whitelisted_devices) und
die einzige Quelle der Wahrheit fuer "wer ist erlaubt". Sie ist
NICHT Teil von devices.

Regeln benutzen ausschliesslich is_whitelisted(). Schreibende
Operationen (add/remove) sind fuer den Menschen bzw. die Admin AI
gedacht und schreiben zusaetzlich in die Geraete-Historie
(whitelist_added / whitelist_removed), falls das Geraet existiert.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from core.inventory.repository import DeviceRepository, InventoryRepositoryError


@dataclass(frozen=True)
class WhitelistEntry:
    """Ein Eintrag in der Whitelist."""
    id: int | None
    timestamp: datetime
    identifier: str
    entity_name: str
    added_by: str | None = None
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "identifier": self.identifier,
            "entity_name": self.entity_name,
            "added_by": self.added_by,
            "notes": self.notes,
        }


class WhitelistRepository:
    """
    Read-only API fuer Regeln + schreibende API fuer den Menschen.

    Liest und schreibt nur die Tabelle whitelisted_devices.
    Schreibende Operationen schreiben zusaetzlich einen History-
    Eintrag ueber DeviceRepository, falls das Geraet existiert.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._devices = DeviceRepository(conn)

    # ------------------------------------------------------------------ #
    # Lesen (read-only API fuer Regeln)
    # ------------------------------------------------------------------ #

    def is_whitelisted(self, identifier: str) -> bool:
        """True, wenn der Identifier auf der Whitelist steht."""
        row = self._conn.execute(
            "SELECT 1 FROM whitelisted_devices WHERE identifier = ?",
            (identifier,),
        ).fetchone()
        return row is not None

    def get(self, identifier: str) -> WhitelistEntry | None:
        row = self._conn.execute(
            "SELECT id, timestamp, identifier, entity_name, added_by, notes "
            "FROM whitelisted_devices WHERE identifier = ?",
            (identifier,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_entry(row)

    def list_all(self) -> list[WhitelistEntry]:
        rows = self._conn.execute(
            "SELECT id, timestamp, identifier, entity_name, added_by, notes "
            "FROM whitelisted_devices ORDER BY timestamp ASC"
        ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def count(self) -> int:
        return self._conn.execute(
            "SELECT COUNT(*) FROM whitelisted_devices"
        ).fetchone()[0]

    def identifiers(self) -> set[str]:
        """Menge aller Identifier auf der Whitelist (fuer Regeln)."""
        rows = self._conn.execute(
            "SELECT identifier FROM whitelisted_devices"
        ).fetchall()
        return {r["identifier"] for r in rows}

    # ------------------------------------------------------------------ #
    # Schreiben (Mensch / Admin AI)
    # ------------------------------------------------------------------ #

    def add(
        self,
        identifier: str,
        entity_name: str,
        *,
        added_by: str | None = None,
        notes: str | None = None,
        timestamp: datetime | None = None,
    ) -> WhitelistEntry:
        """
        Fuegt einen Identifier der Whitelist hinzu.

        Idempotent: existiert der Identifier schon, wird der
        bestehende Eintrag zurueckgegeben und nichts geaendert.
        """
        existing = self.get(identifier)
        if existing is not None:
            return existing

        ts = (timestamp or datetime.now(UTC)).isoformat()
        self._conn.execute(
            "INSERT INTO whitelisted_devices "
            "(timestamp, identifier, entity_name, added_by, notes) "
            "VALUES (?, ?, ?, ?, ?)",
            (ts, identifier, entity_name, added_by, notes),
        )
        self._conn.commit()

        # History-Eintrag, falls das Geraet schon in devices steht.
        self._devices.record_history(
            identifier,
            "whitelist_added",
            data={"added_by": added_by},
            timestamp=timestamp,
        )

        entry = self.get(identifier)
        if entry is None:
            raise InventoryRepositoryError(
                f"Whitelist-Eintrag {identifier!r} nach INSERT nicht gefunden"
            )
        return entry

    def remove(
        self,
        identifier: str,
        *,
        removed_by: str | None = None,
        timestamp: datetime | None = None,
    ) -> bool:
        """
        Entfernt einen Identifier von der Whitelist.

        Rueckgabe: True, wenn ein Eintrag entfernt wurde.
        Schreibt whitelist_removed in die Geraete-Historie,
        falls das Geraet existiert.
        """
        existing = self.get(identifier)
        if existing is None:
            return False

        self._conn.execute(
            "DELETE FROM whitelisted_devices WHERE identifier = ?",
            (identifier,),
        )
        self._conn.commit()

        self._devices.record_history(
            identifier,
            "whitelist_removed",
            data={"removed_by": removed_by},
            timestamp=timestamp,
        )
        return True

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> WhitelistEntry:
        return WhitelistEntry(
            id=row["id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            identifier=row["identifier"],
            entity_name=row["entity_name"],
            added_by=row["added_by"],
            notes=row["notes"],
        )


__all__ = [
    "WhitelistEntry",
    "WhitelistRepository",
]
