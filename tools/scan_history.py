# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tool: scan_history (Punkt 58 Runde 1, Schritt 5, Tool 4).

Filtert audit-logs/YYYY-MM-DD.jsonl auf nmap_scan-Aufrufe.
Kein Service, direkt aus dem Verzeichnis. RBAC uebernimmt
der ToolRunService (tool.db_read).

Signatur folgt dem AgentLoop: tool.func(**args).
Also: scan_history_run(limit=...).
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
_SCAN_TOOL = "nmap_scan"

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

def _is_scan_entry(obj: dict[str, Any]) -> bool:
    details = obj.get("details")
    if not isinstance(details, dict):
        return False
    if details.get("kind") != "tool_call":
        return False
    if details.get("tool") == _SCAN_TOOL:
        return True
    return obj.get("tool") == _SCAN_TOOL

def scan_history_run(limit: int = 20) -> dict[str, Any]:
    """
    Letzte N nmap_scan-Aufrufe aus audit-logs/.

    Fail closed: ungueltiges limit -> ToolError.
    """
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise ToolError("scan_history: 'limit' muss int sein")
    if limit < _LIMIT_MIN or limit > _LIMIT_MAX:
        raise ToolError(
            f"scan_history: 'limit' muss {_LIMIT_MIN}..{_LIMIT_MAX} sein"
        )
    heute = datetime.now(UTC).strftime("%Y-%m-%d")
    pfad = _AUDIT_DIR / f"{heute}.jsonl"
    alle = _read_tail(pfad, limit=1000)
    scans = [e for e in alle if _is_scan_entry(e)]
    scans = scans[-limit:] if len(scans) > limit else scans
    return {
        "scans": scans,
        "count": len(scans),
        "source": "scan_history",
    }

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool

SCAN_HISTORY_TOOL = Tool(
    name="scan_history",
    level=Level.READ,
    func=scan_history_run,
    description="Letzte N nmap_scan-Aufrufe aus audit-logs/.",
    version="0.1.0",
    sandbox_profile="read_only",
    allowed_args=frozenset({"limit"}),
    returns="dict",
)

__all__ = [
    "SCAN_HISTORY_TOOL",
    "scan_history_run",
]
