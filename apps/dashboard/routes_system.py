# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Dashboard-Routen fuer /system (Punkt 66, Kategorie 3).

- GET /system             device.read
- GET /api/system/state   device.read (JSON)

Cache-Control: no-store. Kein CSRF (GET).
Kein Request-Parameter.
"""
from __future__ import annotations

from datetime import UTC, datetime

from flask import Flask, Response, g, jsonify, render_template

from apps.dashboard.decorators import require_permission
from core.services.system_status_service import SystemStatusService


def _build_service() -> SystemStatusService:
    return SystemStatusService(checker=g.access_checker)


def register_system_routes(app: Flask) -> None:

    @app.route("/system", methods=["GET"])
    @require_permission("device.read")
    def system_page() -> str:
        return render_template(
            "system.html",
            page_title="System",
        )

    @app.route("/api/system/state", methods=["GET"])
    @require_permission("device.read")
    def system_state() -> Response:
        svc = _build_service()
        snapshot = svc.get_snapshot(g.principal)
        body = {
            "system": snapshot,
            "timestamp": datetime.now(UTC).isoformat(),
            "available": bool(snapshot.get("available")),
        }
        resp = jsonify(body)
        resp.headers["Cache-Control"] = "no-store"
        return resp


__all__ = ["register_system_routes"]
