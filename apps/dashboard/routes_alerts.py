"""
Dashboard-Routen fuer Alarme.

Kategorie 3 (Route, RBAC, Template).

- GET /alerts    alert.view

Liste der letzten risk_assessment-Eintraege (24h, max 100).
Rein lesend, kein Audit (DESIGN_DECISIONS §11).

Kein Request-Parameter (limit, since_hours) — Service hardcoded.
Kein Route-Level try/except: RBAC via before_request -> 403.
AuditReaderOperationError und IO-Fehler -> globaler 500
(generisch, 3.6.15c). AuditReaderServiceError (Format)
tritt hier nicht auf, weil kein Nutzer-Input direkt geparst wird.
"""
from __future__ import annotations

from flask import Flask, g, render_template

from apps.dashboard.decorators import require_permission
from core.inventory.repository import DeviceRepository
from core.services.audit_reader_service import AuditReaderService


def register_alerts_routes(app: Flask) -> None:
    @app.route("/alerts", methods=["GET"])
    @require_permission("alert.view")
    def alerts_list() -> str:
        service = AuditReaderService(
            audit_writer=g.audit,
            checker=g.access_checker,
            device_repo=DeviceRepository(g.conn),
        )
        assessments = service.list_recent_assessments_with_context(
            g.principal,
        )
        return render_template(
            "alerts.html",
            page_title="Alarme",
            assessments=assessments,
        )


__all__ = ["register_alerts_routes"]
