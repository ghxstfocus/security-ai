"""
Dashboard-Routen fuer Approvals.

Kategorie 3 (Route, RBAC, CSRF, Template).

- GET  /approvals                          approval.view
- GET  /approvals/<request_id>             approval.view
- POST /approvals/<request_id>/decide      approval.decide

CSRF: synchronizer token via apps/dashboard/csrf.
Reihenfolge im POST (Auflage 47):
  1. CSRF pruefen
  2. decision pruefen
  3. reason pruefen (nur Laenge, Whitelist bleibt im Service)
  4. Service entscheiden lassen

Fehler:
- CSRF fehlt/falsch -> 400 (konsistent mit /login).
- decision ungueltig oder fehlt -> 400.
- GET request_id ungueltig oder unbekannt -> 404.
- POST request_id unbekannt -> 404 (ApprovalNotFoundError).
- POST falscher Zustand -> 409 (ApprovalStateError).
- POST request_id ungueltig -> 400 (ApprovalServiceError).
- ApprovalRepositoryError (Basis) -> globaler 500.
- AccessDeniedError -> globaler 403-Handler.
Repo-Fehler werden direkt aus core.approval.repository
importiert und NICHT in ServiceError gewickelt
(Auflage 502-506, Variante D).
Kein str(e) im Response. Kein Logging des request_id (A39).
"""
from __future__ import annotations

from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template,
    request,
    session,
)

from apps.dashboard import csrf
from apps.dashboard.decorators import require_permission
from core.approval.repository import (
    ApprovalNotFoundError,
    ApprovalStateError,
)
from core.services.approval_service import (
    REASON_MAX_LEN,
    ApprovalService,
    ApprovalServiceError,
)
from harness.approval.queue import ApprovalQueue


def _build_service() -> ApprovalService:
    return ApprovalService(
        queue=ApprovalQueue(g.conn, g.audit),
        checker=g.access_checker,
    )


def register_approvals_routes(app: Flask) -> None:
    @app.route("/approvals", methods=["GET"])
    @require_permission("approval.view")
    def approvals_list():
        service = _build_service()
        pending = service.list_pending(g.principal)
        return render_template(
            "approvals.html",
            page_title="Approvals",
            pending=pending,
            csrf_token=csrf.get_or_create(session),
        )

    @app.route("/approvals/<request_id>", methods=["GET"])
    @require_permission("approval.view")
    def approvals_detail(request_id: str):
        service = _build_service()
        try:
            entry = service.get(g.principal, request_id)
        except ApprovalServiceError:
            abort(404)
        if entry is None:
            abort(404)
        return render_template(
            "approval_detail.html",
            page_title="Approval",
            entry=entry,
            csrf_token=csrf.get_or_create(session),
        )

    @app.route(
        "/approvals/<request_id>/decide", methods=["POST"],
    )
    @require_permission("approval.decide")
    def approvals_decide(request_id: str):
        submitted = request.form.get("_csrf_token")
        expected = session.get("_csrf_token")
        if not csrf.validate(submitted, expected):
            return ("Ungueltige Anfrage", 400)
        decision = request.form.get("decision")
        if decision not in ("granted", "rejected"):
            return ("Ungueltige Anfrage", 400)
        reason = request.form.get("reason")
        if reason == "":
            reason = None
        if reason is not None and len(reason) > REASON_MAX_LEN:
            return ("Ungueltige Anfrage", 400)
        service = _build_service()
        try:
            service.decide(
                g.principal, request_id,
                decision=decision, reason=reason,
            )
        except ApprovalNotFoundError:
            abort(404)
        except ApprovalStateError:
            abort(409)
        except ApprovalServiceError:
            return ("Ungueltige Anfrage", 400)
        return redirect("/approvals", 302)


__all__ = ["register_approvals_routes"]
