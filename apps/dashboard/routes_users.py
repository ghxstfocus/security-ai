"""
Dashboard-Routen fuer Benutzer.

Kategorie 3: principal.manage, CSRF, kein password_hash
im View, self-deactivate verboten.

- GET  /users                      principal.manage
- GET  /users/<name>               principal.manage
- GET  /users/new                  principal.manage
- POST /users/new                  principal.manage
- POST /users/<name>/toggle-active principal.manage
- POST /users/<name>/set-password  principal.manage

Kein DELETE, kein delete_principal. Deaktivieren reicht
(Auflage 163).
"""
from __future__ import annotations

from flask import (
    Flask,
    Response,
    abort,
    g,
    render_template,
    request,
    session,
)

from apps.dashboard import csrf
from apps.dashboard._redirect import safe_redirect
from apps.dashboard.decorators import require_permission
from core.access.models import PrincipalKind, principal_to_view
from core.access.repository import AccessNotFoundError
from core.services.access_service import (
    AccessService,
    AccessServiceError,
)


def _build_service() -> AccessService:
    return AccessService.from_conn(g.conn, g.audit)


def register_users_routes(app: Flask) -> None:
    @app.route("/users", methods=["GET"])
    @require_permission("principal.manage")
    def users_list() -> str:
        service = _build_service()
        principals = service.list_principals(g.principal)
        views = [principal_to_view(p) for p in principals]
        return render_template(
            "users.html",
            page_title="Benutzer",
            users=views,
        )

    @app.route("/users/new", methods=["GET"])
    @require_permission("principal.manage")
    def users_new_form() -> str:
        service = _build_service()
        roles = service.list_roles(g.principal)
        return render_template(
            "user_new.html",
            page_title="Neuer Benutzer",
            roles=roles,
            kinds=[k.value for k in PrincipalKind],
            csrf_token=csrf.get_or_create(session),
        )

    @app.route("/users/new", methods=["POST"])
    @require_permission("principal.manage")
    def users_new_post() -> Response | tuple[str, int]:
        submitted = request.form.get("_csrf_token")
        expected = session.get("_csrf_token")
        if not csrf.validate(submitted, expected):
            return ("Ungueltige Anfrage", 400)
        name = request.form.get("name")
        if name is None:
            return ("Ungueltige Anfrage", 400)
        role_name = request.form.get("role_name")
        if role_name is None:
            return ("Ungueltige Anfrage", 400)
        kind_raw = request.form.get("kind")
        is_active_raw = request.form.get("is_active")
        is_active = (is_active_raw == "on")
        password = request.form.get("password") or None
        try:
            kind = PrincipalKind(kind_raw)
        except ValueError:
            return ("Ungueltige Anfrage", 400)
        service = _build_service()
        try:
            service.create_principal(
                g.principal,
                name=name,
                role_name=role_name,
                kind=kind,
                is_active=is_active,
            )
            if password is not None:
                service.set_password(
                    g.principal, name=name, password=password,
                )
        except AccessServiceError:
            return ("Ungueltige Anfrage", 400)
        return safe_redirect("/users", 302)

    @app.route("/users/<name>", methods=["GET"])
    @require_permission("principal.manage")
    def users_detail(name: str) -> str:
        service = _build_service()
        try:
            p = service.get_principal(g.principal, name)
        except AccessServiceError:
            abort(404)
        except AccessNotFoundError:
            abort(404)
        return render_template(
            "user_detail.html",
            page_title="Benutzer",
            entry=principal_to_view(p),
            csrf_token=csrf.get_or_create(session),
        )

    @app.route(
        "/users/<name>/toggle-active", methods=["POST"],
    )
    @require_permission("principal.manage")
    def users_toggle_active(name: str) -> Response | tuple[str, int]:
        submitted = request.form.get("_csrf_token")
        expected = session.get("_csrf_token")
        if not csrf.validate(submitted, expected):
            return ("Ungueltige Anfrage", 400)
        service = _build_service()
        try:
            current = service.get_principal(g.principal, name)
        except (AccessServiceError, AccessNotFoundError):
            abort(404)
        new_state = not current.is_active
        if name == g.principal and new_state is False:
            return ("Ungueltige Anfrage", 400)
        try:
            service.set_principal_active(
                g.principal, name=name, is_active=new_state,
            )
        except (AccessServiceError, AccessNotFoundError):
            abort(404)
        return safe_redirect("/users", 302)

    @app.route(
        "/users/<name>/set-password", methods=["POST"],
    )
    @require_permission("principal.manage")
    def users_set_password(name: str) -> Response | tuple[str, int]:
        submitted = request.form.get("_csrf_token")
        expected = session.get("_csrf_token")
        if not csrf.validate(submitted, expected):
            return ("Ungueltige Anfrage", 400)
        password = request.form.get("password")
        if password is None:
            return ("Ungueltige Anfrage", 400)
        service = _build_service()
        try:
            service.set_password(
                g.principal, name=name, password=password,
            )
        except AccessServiceError:
            return ("Ungueltige Anfrage", 400)
        except AccessNotFoundError:
            abort(404)
        return safe_redirect("/users", 302)


__all__ = ["register_users_routes"]
