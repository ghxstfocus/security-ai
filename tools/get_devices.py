"""
Tool: get_devices (halb-echt).

Liest Geraete aus der Inventory-DB.

Verhalten:
  - mock=True       -> Mock-Ergebnis, kein DB-Zugriff
  - db_path gesetzt -> genau diese Datei. Fehlt sie: ToolError
  - db_path=None    -> Default aus core.inventory.repository.
                       Fehlt die Datei: ToolError

Fail closed. Kein stilles leeres Ergebnis bei fehlender DB.

Signatur folgt dem AgentLoop: tool.func(**args).
Also: get_devices_run(identifier=..., db_path=..., mock=...).
"""
from __future__ import annotations

from datetime import datetime, timezone, UTC
from pathlib import Path
from typing import Any

from core.inventory.repository import (
    DEFAULT_DB_PATH,
    DeviceRepository,
    connect,
)
from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool, ToolArgumentError, ToolError

# ---------------------------------------------------------------------- #
# Validierung
# ---------------------------------------------------------------------- #

def _validate_identifier(identifier: Any) -> str | None:
    if identifier is None:
        return None
    if not isinstance(identifier, str):
        raise ToolArgumentError(
            f"get_devices: 'identifier' muss String sein, "
            f"nicht {type(identifier).__name__}"
        )
    i = identifier.strip()
    if not i:
        raise ToolArgumentError(
            "get_devices: 'identifier' darf nicht leer sein"
        )
    if len(i) > 253:
        raise ToolArgumentError(
            f"get_devices: 'identifier' zu lang ({len(i)} > 253)"
        )
    return i


def _validate_db_path(db_path: Any) -> Path | None:
    if db_path is None:
        return None
    if isinstance(db_path, Path):
        return db_path
    if not isinstance(db_path, str):
        raise ToolArgumentError(
            f"get_devices: 'db_path' muss String oder Path sein, "
            f"nicht {type(db_path).__name__}"
        )
    p = db_path.strip()
    if not p:
        raise ToolArgumentError(
            "get_devices: 'db_path' darf nicht leer sein"
        )
    return Path(p)


def _validate_mock(mock: Any) -> bool:
    if not isinstance(mock, bool):
        raise ToolArgumentError(
            f"get_devices: 'mock' muss bool sein, "
            f"nicht {type(mock).__name__}"
        )
    return mock


# ---------------------------------------------------------------------- #
# Tool-Funktion
# ---------------------------------------------------------------------- #

def get_devices_run(
    identifier: str | None = None,
    db_path: str | Path | None = None,
    mock: bool = False,
) -> dict[str, Any]:
    """
    Liest Geraete aus der Inventory-DB.

    - identifier: wenn gesetzt, nur dieses Geraet
    - db_path:    expliziter Pfad, sonst DEFAULT_DB_PATH
    - mock:       True -> sofort Mock zurueck, kein DB-Zugriff
    """
    ident = _validate_identifier(identifier)
    explicit_path = _validate_db_path(db_path)
    want_mock = _validate_mock(mock)

    now = datetime.now(UTC).isoformat()

    # Mock-Modus: kein DB-Zugriff
    if want_mock:
        devices = []
        if ident:
            devices = [{
                "id": 0,
                "identifier": ident,
                "entity_name": "mock-device",
                "network_type": "Hauptnetz",
                "first_seen": now,
                "last_seen": now,
                "device_type": "unknown",
                "notes": None,
            }]
        return {
            "devices": devices,
            "count": len(devices),
            "source": "mock",
            "read_at": now,
        }

    # DB-Pfad bestimmen
    path = explicit_path or DEFAULT_DB_PATH
    if not path.exists():
        raise ToolError(
            f"get_devices: DB-Datei fehlt: {path}. "
            "Kein stilles leeres Ergebnis (fail closed)."
        )

    conn = connect(path)
    try:
        repo = DeviceRepository(conn)
        if ident:
            dev = repo.get(ident)
            rows = [dev.to_dict()] if dev is not None else []
        else:
            rows = [d.to_dict() for d in repo.list_all()]
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass

    return {
        "devices": rows,
        "count": len(rows),
        "source": "db",
        "read_at": now,
    }


# ---------------------------------------------------------------------- #
# Tool-Definition
# ---------------------------------------------------------------------- #

GET_DEVICES_TOOL = Tool(
    name="get_devices",
    level=Level.READ,
    func=get_devices_run,
    description=(
        "Liest Geraete aus der Inventory-DB. "
        "Fail closed bei fehlender DB. mock=True liefert Mock-Ergebnis."
    ),
    version="0.1.0",
    sandbox_profile="read_only",
    allowed_args=frozenset({"identifier", "db_path", "mock"}),
    returns="dict",
)


__all__ = [
    "GET_DEVICES_TOOL",
    "get_devices_run",
]
