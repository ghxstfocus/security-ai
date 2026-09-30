"""
Dashboard-Route: Polling-Endpoint /api/dashboard/state.

Kategorie 3 (Route, RBAC, JSON, Datei-IO via Service).

- GET /api/dashboard/state  (JSON)
  RBAC: pro Sektion unterschiedlich.
  - devices -> device.read
  - alerts  -> alert.view
  - changes -> change.view
  Fehlende Permission -> Sektion fehlt im JSON
  (kein leerer Platzhalter, fail closed pro Sektion).

- Cache-Control: no-store.
- Kein CSRF (GET, kein State-Change).
- Kein Rate-Limit (5s-Polling von eingeloggten
  Nutzern ist Normalnutzung).
- Kein Request-Parameter.

Rueckgabe-Struktur:
  {
    "devices": {"active": [...], "recent": [...],
                "hauptnetz": N, "gastnetz": M,
                "available": true|false},
    "alerts": [...],
    "changes": [...],
    "timestamp": "ISO-8601-UTC"
  }
Sektion fehlt = Actor hat keine Permission.
"""
from __future__ import annotations

from datetime import UTC, datetime

from flask import Flask, Response, g, jsonify

from apps.dashboard.decorators import require_permission
from core.access.checker import AccessDeniedError
from core.changes.repository import ChangeRepository
from core.inventory.repository import DeviceRepository
from core.inventory.whitelist import WhitelistRepository
from core.services.audit_reader_service import AuditReaderService
from core.services.change_service import ChangeService
from core.services.fritzbox_state_service import FritzboxStateService
from core.services.inventory_service import InventoryService


def _section_devices() -> dict | None:
    """Geraete-Sektion (device.read). Fehlt bei AccessDeniedError."""
    try:
        inv = InventoryService(
            device_repo=DeviceRepository(g.conn),
            whitelist_repo=WhitelistRepository(g.conn),
            checker=g.access_checker,
        )
        state = FritzboxStateService(g.access_checker).get_state(
            g.principal,
        )
        devices = inv.list_devices(g.principal)
        counts = inv.count_by_network(g.principal)
        hosts = state.get("hosts", {}) if state.get("available") else {}
        active_macs = [
            mac for mac, info in hosts.items()
            if isinstance(info, dict) and info.get("active") is True
        ]
        active_set = set(active_macs)
        active = [d for d in devices if d.get("identifier") in active_set]
        recent = devices[:5]
        return {
            "active": active,
            "recent": recent,
            "hauptnetz": counts.get("Hauptnetz", 0),
            "gastnetz": counts.get("Gastnetz", 0),
            "available": bool(state.get("available")),
        }
    except AccessDeniedError:
        return None


def _section_alerts() -> list | None:
    """Alarme-Sektion (alert.view). Fehlt bei AccessDeniedError."""
    try:
        svc = AuditReaderService(
            audit_writer=g.audit,
            checker=g.access_checker,
        )
        return svc.list_recent_assessments(g.principal, limit=5)
    except AccessDeniedError:
        return None


def _section_changes() -> list | None:
    """Changes-Sektion (change.view). Fehlt bei AccessDeniedError."""
    try:
        svc = ChangeService(
            repo=ChangeRepository(g.conn),
            checker=g.access_checker,
            audit_writer=g.audit,
        )
        return svc.list_all(g.principal)[:5]
    except AccessDeniedError:
        return None


def register_state_routes(app: Flask) -> None:

    @app.route("/api/dashboard/state", methods=["GET"])
    @require_permission("device.read")
    def dashboard_state() -> Response:
        devices = _section_devices()
        alerts = _section_alerts()
        changes = _section_changes()
        body: dict = {
            "timestamp": datetime.now(UTC).isoformat(),
        }
        if devices is not None:
            body["devices"] = devices
        if alerts is not None:
            body["alerts"] = alerts
        if changes is not None:
            body["changes"] = changes
        resp = jsonify(body)
        resp.headers["Cache-Control"] = "no-store"
        return resp


__all__ = ["register_state_routes"]
