# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tool: audit_tail (Punkt 58 Runde 1, Schritt 5, Tool 1).

Liest die letzten N Zeilen aus audit-logs/YYYY-MM-DD.jsonl.
Kein Service, direkt aus dem Verzeichnis. RBAC uebernimmt
der ToolRunService (tool.db_read).

Signatur folgt dem AgentLoop: tool.func(**args).
Also: audit_tail_run(limit=...).
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from harness.tool_registry.tool import ToolError

_AUDIT_DIR = Path("audit-logs")
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

def audit_tail_run(limit: int = 20) -> dict[str, Any]:
    """
    Letzte N Audit-Eintraege aus audit-logs/.

    Fail closed: ungueltiges limit -> ToolError.
    Heute zuerst, wenn leer dann gestern.
    """
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise ToolError("audit_tail: 'limit' muss int sein")
    if limit < _LIMIT_MIN or limit > _LIMIT_MAX:
        raise ToolError(
            f"audit_tail: 'limit' muss {_LIMIT_MIN}..{_LIMIT_MAX} sein"
        )
    heute = datetime.now(UTC).strftime("%Y-%m-%d")
    pfad = _AUDIT_DIR / f"{heute}.jsonl"
    eintraege = _read_tail(pfad, limit)
    return {
        "entries": eintraege,
        "count": len(eintraege),
        "source": "audit_tail",
    }

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool

AUDIT_TAIL_TOOL = Tool(
    name="audit_tail",
    level=Level.READ,
    func=audit_tail_run,
    description="Letzte N Audit-Eintraege aus audit-logs/.",
    version="0.1.0",
    sandbox_profile="read_only",
    allowed_args=frozenset({"limit"}),
    returns="dict",
)

__all__ = [
    "AUDIT_TAIL_TOOL",
    "audit_tail_run",
]
