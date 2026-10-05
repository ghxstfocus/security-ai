# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tool: device_history (Punkt 58 Runde 1, Schritt 5, Tool 3).

Liest den Verlauf eines Geraets aus device_history (DB).
Kein Service, direkt ueber DeviceRepository. RBAC uebernimmt
der ToolRunService (tool.db_read).

Signatur folgt dem AgentLoop: tool.func(**args).
Also: device_history_run(identifier=..., limit=...).
"""
from __future__ import annotations

import re
from typing import Any

from core.inventory.repository import (
    DEFAULT_DB_PATH,
    DeviceRepository,
    connect,
)
from harness.tool_registry.tool import (
    ToolArgumentValueError,
    ToolError,
)

_IDENT_RE = re.compile(r"^[0-9A-Fa-f:]{1,32}$")
_LIMIT_MIN = 1
_LIMIT_MAX = 200

def device_history_run(identifier: str, limit: int = 50) -> dict[str, Any]:
    """
    Verlauf eines Geraets (neueste zuerst).

    Fail closed: ungueltiger identifier, ungueltiges limit,
    DB-Fehler -> ToolError.
    """
    if not isinstance(identifier, str):
        raise ToolArgumentValueError("device_history: 'identifier' muss String sein")
    ident = identifier.strip()
    if not _IDENT_RE.match(ident):
        raise ToolArgumentValueError("device_history: 'identifier' ungueltig")
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise ToolArgumentValueError("device_history: 'limit' muss int sein")
    if limit < _LIMIT_MIN or limit > _LIMIT_MAX:
        raise ToolArgumentValueError(
            f"device_history: 'limit' muss {_LIMIT_MIN}..{_LIMIT_MAX} sein"
        )
    try:
        conn = connect(DEFAULT_DB_PATH)
    except Exception as exc:
        raise ToolError(f"device_history: DB-Fehler: {exc}") from exc
    try:
        repo = DeviceRepository(conn)
        entries = repo.history(ident, limit=limit)
    finally:
        conn.close()
    return {
        "identifier": ident,
        "entries": entries,
        "count": len(entries),
        "source": "device_history",
    }

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool

DEVICE_HISTORY_TOOL = Tool(
    name="device_history",
    level=Level.READ,
    func=device_history_run,
    description="Verlauf eines Geraets (device_history).",
    version="0.1.0",
    sandbox_profile="read_only",
    allowed_args=frozenset({"identifier", "limit"}),
    returns="dict",
)

__all__ = [
    "DEVICE_HISTORY_TOOL",
    "device_history_run",
]
