# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tool: whitelist_check.

Zwei Modi:
  - identifier gesetzt -> is_whitelisted fuer genau diesen
  - identifier=None    -> Liste aller Whitelist-Identifier

Fail closed bei fehlender DB. Mock-Modus ohne DB-Zugriff.

Signatur folgt dem AgentLoop: tool.func(**args).
Also: whitelist_check_run(identifier=..., db_path=..., mock=...).

Ergebnis-Struktur:
  identifier=None:
    identifiers, count, source, read_at
  identifier=str:
    identifier, is_whitelisted, count, source, read_at

Kein "mock"-Feld. Nur "source" ("db" oder "mock").
is_whitelisted ist NUR bei identifier-Abfrage vorhanden,
nicht None bei Liste-Abfrage.
"""
from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.inventory.repository import DEFAULT_DB_PATH, connect
from core.inventory.whitelist import WhitelistRepository
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
            f"whitelist_check: 'identifier' muss String sein, "
            f"nicht {type(identifier).__name__}"
        )
    i = identifier.strip()
    if not i:
        raise ToolArgumentError(
            "whitelist_check: 'identifier' darf nicht leer sein"
        )
    if len(i) > 253:
        raise ToolArgumentError(
            f"whitelist_check: 'identifier' zu lang ({len(i)} > 253)"
        )
    return i


def _validate_db_path(db_path: Any) -> Path | None:
    if db_path is None:
        return None
    if isinstance(db_path, Path):
        return db_path
    if not isinstance(db_path, str):
        raise ToolArgumentError(
            f"whitelist_check: 'db_path' muss String oder Path sein, "
            f"nicht {type(db_path).__name__}"
        )
    p = db_path.strip()
    if not p:
        raise ToolArgumentError(
            "whitelist_check: 'db_path' darf nicht leer sein"
        )
    return Path(p)


def _validate_mock(mock: Any) -> bool:
    if not isinstance(mock, bool):
        raise ToolArgumentError(
            f"whitelist_check: 'mock' muss bool sein, "
            f"nicht {type(mock).__name__}"
        )
    return mock


# ---------------------------------------------------------------------- #
# Tool-Funktion
# ---------------------------------------------------------------------- #

def whitelist_check_run(
    identifier: str | None = None,
    db_path: str | Path | None = None,
    mock: bool = False,
) -> dict[str, Any]:
    """
    Prueft die Whitelist.

    - identifier gesetzt: is_whitelisted fuer genau diesen
    - identifier=None:    Liste aller Whitelist-Identifier
    """
    ident = _validate_identifier(identifier)
    explicit_path = _validate_db_path(db_path)
    want_mock = _validate_mock(mock)

    now = datetime.now(UTC).isoformat()

    # Mock-Modus
    if want_mock:
        if ident is not None:
            return {
                "identifier": ident,
                "is_whitelisted": False,
                "count": 0,
                "source": "mock",
                "read_at": now,
            }
        return {
            "identifiers": [],
            "count": 0,
            "source": "mock",
            "read_at": now,
        }

    # DB-Pfad
    path = explicit_path or DEFAULT_DB_PATH
    if not path.exists():
        raise ToolError(
            f"whitelist_check: DB-Datei fehlt: {path}. "
            "Kein stilles leeres Ergebnis (fail closed)."
        )

    conn = connect(path)
    try:
        wl = WhitelistRepository(conn)
        if ident is not None:
            hit = wl.is_whitelisted(ident)
            return {
                "identifier": ident,
                "is_whitelisted": hit,
                "count": 1 if hit else 0,
                "source": "db",
                "read_at": now,
            }
        ids = sorted(wl.identifiers())
        return {
            "identifiers": ids,
            "count": len(ids),
            "source": "db",
            "read_at": now,
        }
    finally:
        with contextlib.suppress(Exception):
            conn.close()


# ---------------------------------------------------------------------- #
# Tool-Definition
# ---------------------------------------------------------------------- #

WHITELIST_CHECK_TOOL = Tool(
    name="whitelist_check",
    level=Level.READ,
    func=whitelist_check_run,
    description="Prueft, ob ein Identifier auf der Whitelist steht.",
    version="0.1.0",
    sandbox_profile="read_only",
    allowed_args=frozenset({"identifier", "db_path", "mock"}),
    returns="dict",
)


__all__ = [
    "WHITELIST_CHECK_TOOL",
    "whitelist_check_run",
]
