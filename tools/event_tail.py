# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tool: event_tail (Punkt 58 Runde 1, Schritt 5, Tool 2).

Liest die letzten N Zeilen aus data/events-YYYY-MM-DD.jsonl.
Kein Service, direkt aus dem Verzeichnis. RBAC uebernimmt
der ToolRunService (tool.db_read).

Signatur folgt dem AgentLoop: tool.func(**args).
Also: event_tail_run(limit=...).
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from harness.tool_registry.tool import ToolError

_EVENTS_DIR = Path("data")
_LIMIT_MIN = 1
_LIMIT_MAX = 100

def _read_tail(path: Path, limit: int) -> list[dict[str, Any]]:
    """Liest die letzten `limit` JSON-Zeilen. Fehlerhafte
    Zeilen werden uebersprungen (append-only Log)."""
    if not path.exists():
        return []
    zeilen = path.read_text(encoding="utf-8").splitlines()
    letzte = zeilen[-limit:] if len(zeilen) > limit else zeilen
    out: list[dict[str, Any]] = []
    for z in letzte:
        z = z.strip()
        if not z:
            continue
        try:
            obj = json.loads(z)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out

def event_tail_run(limit: int = 20) -> dict[str, Any]:
    """
    Letzte N Events aus data/events-YYYY-MM-DD.jsonl.

    Fail closed: ungueltiges limit -> ToolError.
    """
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise ToolError("event_tail: 'limit' muss int sein")
    if limit < _LIMIT_MIN or limit > _LIMIT_MAX:
        raise ToolError(
            f"event_tail: 'limit' muss {_LIMIT_MIN}..{_LIMIT_MAX} sein"
        )
    heute = datetime.now(UTC).strftime("%Y-%m-%d")
    pfad = _EVENTS_DIR / f"events-{heute}.jsonl"
    events = _read_tail(pfad, limit)
    return {
        "events": events,
        "count": len(events),
        "source": "event_tail",
    }

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool

EVENT_TAIL_TOOL = Tool(
    name="event_tail",
    level=Level.READ,
    func=event_tail_run,
    description="Letzte N Events aus data/events-YYYY-MM-DD.jsonl.",
    version="0.1.0",
    sandbox_profile="read_only",
    allowed_args=frozenset({"limit"}),
    returns="dict",
)

__all__ = [
    "EVENT_TAIL_TOOL",
    "event_tail_run",
]
