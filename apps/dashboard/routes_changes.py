"""
Dashboard-Routen fuer Change Requests.

Kategorie 3 (Route, RBAC, CSRF, Templates, Schreibpfad).

- GET  /changes                  change.view
- GET  /changes/<change_id>      change.view
- GET  /changes/new              change.create
- POST /changes/new              change.create

CSRF: synchronizer token via apps/dashboard/csrf.
Reihenfolge im POST:
  1. CSRF pruefen
  2. Pflichtfelder lesen
  3. Service validiert + schreibt + auditiert
Fehler (K1):
- ChangeServiceError    -> 400 (Format).
- ChangeOperationError  -> NICHT fangen, globaler 500-Handler.
- CSRF fehlt/falsch     -> 400.
- change_id ungueltig/unbekannt -> 404.
- AccessDeniedError     -> 403 (global).
"""
from __future__ import annotations

from flask import (
    Flask,
    Response,
    abort,
    g,
    redirect,
    render_template,
    request,
    session,
)

from apps.dashboard import csrf
from apps.dashboard.decorators import require_permission
from core.changes.repository import ChangeRepository
from core.services.change_service import (
    VALID_TYPES,
    ChangeService,
    ChangeServiceError,
)


def _build_service() -> ChangeService:
    return ChangeService(
        repo=ChangeRepository(g.conn),
        checker=g.access_checker,
        audit_writer=g.audit,
    )


def register_changes_routes(app: Flask) -> None:
    @app.route("/changes", methods=["GET"])
    @require_permission("change.view")
    def changes_list() -> str:
        service = _build_service()
        changes = service.list_all(g.principal)
        return render_template(
            "changes.html",
            page_title="Changes",
            changes=changes,
        )

    @app.route("/changes/new", methods=["GET"])
    @require_permission("change.create")
    def changes_new_form() -> str:
        return render_template(
            "change_new.html",
            page_title="Neuer Change",
            types=VALID_TYPES,
            csrf_token=csrf.get_or_create(session),
        )

    @app.route("/changes/new", methods=["POST"])
    @require_permission("change.create")
    def changes_new_post() -> Response | tuple[str, int]:
        submitted = request.form.get("_csrf_token")
        expected = session.get("_csrf_token")
        if not csrf.validate(submitted, expected):
            return ("Ungueltige Anfrage", 400)
        title = request.form.get("title")
        description = request.form.get("description")
        ctype = request.form.get("type")
        diff_or_patch = request.form.get("diff_or_patch")
        files_affected = request.form.get("files_affected")
        rollback_plan = request.form.get("rollback_plan")
        test_plan = request.form.get("test_plan")
        service = _build_service()
        try:
            service.create(
                g.principal,
                title=title,
                description=description,
                type=ctype,
                diff_or_patch=diff_or_patch or None,
                files_affected=files_affected or None,
                rollback_plan=rollback_plan or None,
                test_plan=test_plan or None,
            )
        except ChangeServiceError:
            return ("Ungueltige Anfrage", 400)
        return redirect("/changes", 302)

    @app.route("/changes/<change_id>", methods=["GET"])
    @require_permission("change.view")
    def changes_detail(change_id: str) -> str:
        service = _build_service()
        try:
            entry = service.get(g.principal, change_id)
        except ChangeServiceError:
            abort(404)
        if entry is None:
            abort(404)
        return render_template(
            "change_detail.html",
            page_title="Change",
            entry=entry,
        )


__all__ = ["register_changes_routes"]
