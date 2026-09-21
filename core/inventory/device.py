"""
Domaenen-Modell fuer Geraete im Inventory.

Ein Device beschreibt, was wir gesehen haben. Es beschreibt NICHT,
ob das Geraet erlaubt ist — das ist Sache der Whitelist
(core/inventory/whitelist.py).

Device ist unveraenderlich (frozen=True). Aenderungen erzeugen ein
neues Device. Der DB-Zugriff liegt in repository.py.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class DeviceType(str, Enum):
    """Grobe Klassifikation eines Geraets."""
    SERVER = "server"
    CLIENT = "client"
    IOT = "iot"
    NETWORK = "network"
    UNKNOWN = "unknown"

    def __str__(self) -> str:  # pragma: no cover
        return self.value


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Device:
    """
    Ein Geraet im Inventory.

    - identifier:   eindeutige Kennung (aktuell IP, spaeter auch MAC/RFID)
    - entity_name:  lesbarer Name, optional
    - network_type: "Hauptnetz" | "Gastnetz" | "Extern" | ...
    - first_seen:   erster Auftritt (UTC)
    - last_seen:    letzter Auftritt (UTC)
    - device_type:  grobe Klassifikation
    - notes:        freies Textfeld
    - id:           DB-ID, erst nach Insert gesetzt (None vorher)
    """
    identifier: str
    entity_name: str | None = None
    network_type: str | None = None
    first_seen: datetime = field(default_factory=_utc_now)
    last_seen: datetime = field(default_factory=_utc_now)
    device_type: DeviceType = DeviceType.UNKNOWN
    notes: str | None = None
    id: int | None = None

    def __post_init__(self) -> None:
        if not self.identifier or not isinstance(self.identifier, str):
            raise ValueError("identifier muss ein nicht-leerer String sein")
        if self.first_seen.tzinfo is None:
            raise ValueError("first_seen muss timezone-aware sein")
        if self.last_seen.tzinfo is None:
            raise ValueError("last_seen muss timezone-aware sein")

    def to_dict(self) -> dict[str, Any]:
        """Serialisierbares Dict (Zeitstempel als ISO-8601-Strings)."""
        return {
            "id": self.id,
            "identifier": self.identifier,
            "entity_name": self.entity_name,
            "network_type": self.network_type,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "device_type": self.device_type.value,
            "notes": self.notes,
        }

    @classmethod
    def from_row(cls, row: Any) -> "Device":
        """
        Baut ein Device aus einer sqlite3.Row.

        Erwartet Spalten: id, identifier, entity_name, network_type,
        first_seen, last_seen, notes (device_type ist nicht in der DB —
        die Klassifikation kommt spaeter, Default UNKNOWN).
        """
        keys = row.keys() if hasattr(row, "keys") else []
        device_type_value = row["device_type"] if "device_type" in keys else None
        try:
            device_type = DeviceType(device_type_value) if device_type_value else DeviceType.UNKNOWN
        except ValueError:
            device_type = DeviceType.UNKNOWN

        return cls(
            id=row["id"],
            identifier=row["identifier"],
            entity_name=row["entity_name"],
            network_type=row["network_type"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            device_type=device_type,
            notes=row["notes"],
        )


__all__ = [
    "Device",
    "DeviceType",
]
