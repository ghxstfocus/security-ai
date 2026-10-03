# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Dashboard-Routen fuer Alarme.

Kategorie 3 (Route, RBAC, Template).

- GET /alerts    alert.view

Liste der risk_assessment-Eintraege mit Filter und
Pagination (Punkt 80). Rein lesend, kein Audit
(DESIGN_DECISIONS §11).

Query-Parameter (alle optional):
- since: 24 | 168 | 720 (Stunden).
- category: in CATEGORY_LABELS.
- identifier: MAC-Format.
- network_type: Hauptnetz | Gastnetz | Extern.
- q: 2..200 Zeichen.
- page: >= 1.

Ungueltige Werte -> AuditReaderServiceError -> 400.
Kein Route-Level except fuer generische Fehler.
"""
from __future__ import annotations

from flask import Flask, g, render_template, request

from apps.dashboard.decorators import require_permission
from core.inventory.repository import DeviceRepository
from core.risk.models import CATEGORY_LABELS
from core.services.audit_reader_service import (
    NETWORK_TYPE_VALUES,
    SINCE_HOURS_VALUES,
    AuditReaderService,
    AuditReaderServiceError,
)


def register_alerts_routes(app: Flask) -> None:
    @app.route("/alerts", methods=["GET"])
    @require_permission("alert.view")
    def alerts_list() -> str | tuple[str, int]:
        # Query-Parameter (Punkt 80).
        since_raw = request.args.get("since")
        since_hours = (
            int(since_raw) if since_raw and since_raw.isdigit()
            else 24
        )
        category = request.args.get("category") or None
        identifier = request.args.get("identifier") or None
        network_type = request.args.get("network_type") or None
        q = request.args.get("q") or None
        page_raw = request.args.get("page")
        page = (
            int(page_raw) if page_raw and page_raw.isdigit()
            else 1
        )

        device_repo = DeviceRepository(g.conn)
        service = AuditReaderService(
            audit_writer=g.audit,
            checker=g.access_checker,
            device_repo=device_repo,
        )
        try:
            result = service.list_recent_assessments_with_context(
                g.principal,
                since_hours=since_hours,
                category=category,
                identifier=identifier,
                network_type=network_type,
                q=q,
                page=page,
            )
        except AuditReaderServiceError:
            return ("Ungueltige Anfrage", 400)

        devices = device_repo.list_all()
        return render_template(
            "alerts.html",
            page_title="Alarme",
            assessments=result["items"],
            total=result["total"],
            page=result["page"],
            pages=result["pages"],
            per_page=result["per_page"],
            devices=devices,
            filter_since=since_hours,
            filter_category=category or "",
            filter_identifier=identifier or "",
            filter_network_type=network_type or "",
            filter_q=q or "",
            since_values=SINCE_HOURS_VALUES,
            network_type_values=NETWORK_TYPE_VALUES,
            category_values=CATEGORY_LABELS,
        )


__all__ = ["register_alerts_routes"]
