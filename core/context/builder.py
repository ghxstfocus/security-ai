"""
Kontext-Bauer fuer den Chat (Punkt 28, 2026-09-27).

Baut den Kontext, den ChatService.ask erwartet, aus
DB und audit-logs. Kein RBAC, kein Audit.

Wird von CLI (scripts/chat_cli.py) und Dashboard
(apps/dashboard/routes_chat.py) genutzt.

Log-Excerpts und recent_events sind leer (Auflagen
720/721). Sie brauchen eine eigene Redaction-Bewertung
(DESIGN_DECISIONS §15) bzw. eine Event-Historie
(Phase >4).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from core.approval.repository import ApprovalRepository
from core.changes.repository import ChangeRepository
from core.inventory.repository import DeviceRepository
from core.inventory.whitelist import WhitelistRepository
from core.reporting.audit_reader import read_risk_assessments
from core.reporting.inventory_snapshot import build_inventory_snapshot


def build_chat_context(
    conn: sqlite3.Connection,
    audit_base_dir: Path | str,
    *,
    since_hours: int = 24,
    max_assessments: int = 50,
) -> dict[str, object]:
    """
    Liefert ein dict mit den Schluesseln, die ChatService.ask
    als Keyword-Argumente akzeptiert.

    Reine Funktion. Fehler propagieren (kein fail silent).
    """
    devices = DeviceRepository(conn).list_all()
    whitelist_ids = WhitelistRepository(conn).identifiers()
    inventory_snapshot = build_inventory_snapshot(
        devices, whitelist_ids,
    )
    open_approvals = tuple(ApprovalRepository(conn).list_pending())
    open_changes = tuple(ChangeRepository(conn).list_pending())
    risk_assessments = tuple(read_risk_assessments(
        audit_base_dir,
        since_hours=since_hours,
        max_entries=max_assessments,
    ))
    return {
        "risk_assessments": risk_assessments,
        "inventory_snapshot": inventory_snapshot,
        "open_approvals": open_approvals,
        "open_changes": open_changes,
        # Auflage 720: Log-Excerpts bleiben leer.
        # Sie brauchen eine eigene Redaction-Bewertung
        # (DESIGN_DECISIONS §15).
        "log_excerpts": (),
        # Auflage 721: Events werden nicht persistiert.
        # recent_events ist ein Platzhalter fuer Phase >4.
        "recent_events": (),
    }


__all__ = ["build_chat_context"]
