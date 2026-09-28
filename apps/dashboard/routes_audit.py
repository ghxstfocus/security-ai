"""
Dashboard-Routen fuer Audit.

Kategorie 3: audit.read, read-only, kein Audit fuer das
Lesen von Audit (DESIGN_DECISIONS §11).

Fehler-Mapping (A195, A201, 3.6.15c):
- Query-Parameter date falsch -> 400 (Nutzer sieht ihn).
- Pfad-Parameter audit_id falsch -> 404 (URL-Standard).
- AuditReaderOperationError (Konstruktor-None, IO)
  -> NICHT fangen, globaler 500.

- GET /audit                  audit.read
- GET /audit/<audit_id>       audit.read

Kein "Alle Tage"-Link (A197): read_all im UI waere
DoS-Vektor.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timezone

from flask import (
    Flask,
    abort,
    g,
    render_template,
    request,
)

from apps.dashboard.decorators import require_permission
from core.services.audit_reader_service import (
    AuditReaderService,
    AuditReaderServiceError,
)


def _build_service() -> AuditReaderService:
    return AuditReaderService(
        audit_writer=g.audit,
        checker=g.access_checker,
    )


def _details_formatted(entry: dict) -> str:
    """Auflage 198, 203: details serverseitig formatiert."""
    raw = entry.get("details")
    if raw is None:
        return ""
    try:
        return json.dumps(raw, indent=2, sort_keys=True,
                          ensure_ascii=True)
    except (TypeError, ValueError):
        return ""


def register_audit_routes(app: Flask) -> None:
    @app.route("/audit", methods=["GET"])
    @require_permission("audit.read")
    def audit_list():
        date_arg = request.args.get("date")
        if date_arg is None:
            date_str = datetime.now(UTC).strftime(
                "%Y-%m-%d",
            )
        else:
            date_str = date_arg
        service = _build_service()
        try:
            entries = service.read_day(g.principal, date_str)
        except AuditReaderServiceError:
            return ("Ungueltige Anfrage", 400)
        return render_template(
            "audit.html",
            page_title="Audit",
            date=date_str,
            entries=entries,
        )

    @app.route("/audit/<audit_id>", methods=["GET"])
    @require_permission("audit.read")
    def audit_detail(audit_id: str):
        service = _build_service()
        try:
            entry = service.find_by_audit_id(g.principal, audit_id)
        except AuditReaderServiceError:
            abort(404)
        if entry is None:
            abort(404)
        return render_template(
            "audit_detail.html",
            page_title="Audit-Eintrag",
            entry=entry,
            details_formatted=_details_formatted(entry),
        )


__all__ = ["register_audit_routes"]
