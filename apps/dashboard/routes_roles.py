"""
Dashboard-Routen fuer Rollen.

Kategorie 3: role.manage, CSRF, kein row_id im View,
role_name-Validierung in der Route (Ausnahme, weil der
Service heute keine Rolle-Name-Validierung hat).

Audit erfolgt in AccessService.assign_permission /
revoke_permission. Die Route schreibt kein Audit
(Auflage 189).

create_role / delete_role nicht in 3.6.8g.
Rollen-Anlage ist Policy, eigene Runde (Auflage 179).

- GET  /roles                          role.manage
- GET  /roles/<name>                   role.manage
- POST /roles/<name>/assign-permission role.manage
- POST /roles/<name>/revoke-permission role.manage
"""
from __future__ import annotations

import re

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
from core.access.models import (
    permission_to_view,
    role_to_view,
)
from core.access.repository import AccessNotFoundError
from core.services.access_service import (
    AccessService,
    AccessServiceError,
)

ROLE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
PERMISSION_CODE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _build_service() -> AccessService:
    return AccessService.from_conn(g.conn, g.audit)


def _valid_role_name(name: str) -> bool:
    return isinstance(name, str) and bool(ROLE_NAME_RE.match(name))


def register_roles_routes(app: Flask) -> None:
    @app.route("/roles", methods=["GET"])
    @require_permission("role.manage")
    def roles_list():
        service = _build_service()
        roles = service.list_roles(g.principal)
        views = [role_to_view(r) for r in roles]
        return render_template(
            "roles.html",
            page_title="Rollen",
            roles=views,
        )

    @app.route("/roles/<name>", methods=["GET"])
    @require_permission("role.manage")
    def roles_detail(name: str):
        if not _valid_role_name(name):
            abort(404)
        service = _build_service()
        try:
            role = service.get_role(g.principal, name)
        except AccessServiceError:
            abort(404)
        except AccessNotFoundError:
            abort(404)
        perms = service.list_permissions(g.principal)
        perms_view = [permission_to_view(p) for p in perms]
        role_view = role_to_view(role)
        # Auflage 190-192: Warnung, wenn eigene Rolle UND
        # die Rolle role.manage oder principal.manage hat.
        own_role = g.access_checker.role_of(g.principal)
        warn_self = False
        if own_role is not None and own_role == role_view["name"]:
            perms_set = set(role_view["permissions"])
            if ("role.manage" in perms_set
                    or "principal.manage" in perms_set):
                warn_self = True
        return render_template(
            "role_detail.html",
            page_title="Rolle",
            role=role_view,
            all_permissions=perms_view,
            warn_self=warn_self,
            current_actor=g.principal,
            csrf_token=csrf.get_or_create(session),
        )

    @app.route(
        "/roles/<name>/assign-permission", methods=["POST"],
    )
    @require_permission("role.manage")
    def roles_assign_permission(name: str):
        if not _valid_role_name(name):
            abort(404)
        submitted = request.form.get("_csrf_token")
        expected = session.get("_csrf_token")
        if not csrf.validate(submitted, expected):
            return ("Ungueltige Anfrage", 400)
        code = request.form.get("permission_code")
        if not isinstance(code, str) or not PERMISSION_CODE_RE.match(code):
            return ("Ungueltige Anfrage", 400)
        service = _build_service()
        try:
            service.assign_permission(
                g.principal,
                role_name=name,
                permission_code=code,
            )
        except AccessServiceError:
            abort(404)
        except AccessNotFoundError:
            abort(404)
        return redirect(f"/roles/{name}", 302)

    @app.route(
        "/roles/<name>/revoke-permission", methods=["POST"],
    )
    @require_permission("role.manage")
    def roles_revoke_permission(name: str):
        if not _valid_role_name(name):
            abort(404)
        submitted = request.form.get("_csrf_token")
        expected = session.get("_csrf_token")
        if not csrf.validate(submitted, expected):
            return ("Ungueltige Anfrage", 400)
        code = request.form.get("permission_code")
        if not isinstance(code, str) or not PERMISSION_CODE_RE.match(code):
            return ("Ungueltige Anfrage", 400)
        service = _build_service()
        try:
            service.revoke_permission(
                g.principal,
                role_name=name,
                permission_code=code,
            )
        except AccessServiceError:
            abort(404)
        except AccessNotFoundError:
            abort(404)
        return redirect(f"/roles/{name}", 302)


__all__ = ["register_roles_routes"]
