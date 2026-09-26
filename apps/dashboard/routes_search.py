"""
Dashboard-Route fuer die globale Suche.

Kategorie 3 (3.6.16, Auflagen 523-552).

- GET /search?q=...    search.run

Rein lesend, kein Audit (DESIGN_DECISIONS §11).
Validierung im Service (Auflage 538); die Route
reicht q roh weiter.

Fehler:
- SearchServiceError (Format) -> 400, generischer Text,
  KEIN Echo von q (Auflage 551).
- Permission fehlt -> 403 via before_request.
- Sonstige Fehler -> globaler 500.
"""
from __future__ import annotations

from flask import Flask, g, render_template, request

from apps.dashboard.decorators import require_permission
from core.reporting.audit_reader import read_risk_assessments
from core.search.repository import SearchRepository
from core.services.search_service import (
    SearchService,
    SearchServiceError,
)


def _build_service() -> SearchService:
    return SearchService(
        repo=SearchRepository(g.conn),
        audit_reader=read_risk_assessments,
        checker=g.access_checker,
    )


def register_search_routes(app: Flask) -> None:
    @app.route("/search", methods=["GET"])
    @require_permission("search.run")
    def search_view():
        q_raw = request.args.get("q", "")
        service = _build_service()
        try:
            results = service.search(g.principal, q_raw)
        except SearchServiceError:
            return ("Ungueltige Anfrage", 400)
        return render_template(
            "search.html",
            page_title="Suche",
            q=q_raw,
            results=results,
        )


__all__ = ["register_search_routes"]
