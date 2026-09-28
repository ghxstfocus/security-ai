"""
Flask-App-Factory fuer das Web-Dashboard (Phase 3.6).

Sicherheitsregeln (WEB_SECURITY_CHECKLIST.md):
- DEBUG=False, TESTING=False, PROPAGATE_EXCEPTIONS=False.
- SECRET_KEY aus .env (get_secret_key).
- Cookies: HttpOnly, Secure, SameSite=Strict.
- Session-Timeout: 30 min idle.
- RBAC-Pruefung im before_request (ein Ort).
- Kein DB-Zugriff in Routes (nur Services).
- AuditWriter ist App-Singleton in app.extensions.
"""
from __future__ import annotations

import os
import pwd
from datetime import datetime, timedelta, timezone, UTC

from flask import Flask, g, redirect, request
from werkzeug.exceptions import HTTPException

from apps.dashboard.decorators import (
    SESSION_COOKIE_NAME,
    is_public_path,
)
from core.access.checker import (
    AccessChecker,
    AccessDeniedError,
)
from core.access.session_repo import SessionRepository
from core.config import get_secret_key
from core.inventory.repository import (
    DEFAULT_DB_PATH,
    DEFAULT_MIGRATIONS_DIR,
    SchemaVersionError,
    check_schema_version,
    connect,
)
from core.services.access_service import AccessService
from harness.audit.writer import (
    AuditWriter,
    check_audit_logs,
)

DEFAULT_AUDIT_DIR = "audit-logs"
IDLE_TIMEOUT_SECONDS = 30 * 60


def create_app(
    *,
    check_audit: bool = True,
    check_schema: bool = True,
    db_path=DEFAULT_DB_PATH,
    migrations_dir=DEFAULT_MIGRATIONS_DIR,
    audit_base_dir: str = DEFAULT_AUDIT_DIR,
    secret_key: str | None = None,
) -> Flask:
    app = Flask(__name__)

    # Punkt 16 (Auflage 649): ProxyFix nur, weil
    # nginx der einzige vorgelagerte Proxy ist
    # (Flask bindet auf 127.0.0.1:5000). Bei einem
    # zweiten Proxy: neue Bewertung, Werte anpassen.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1, x_proto=1, x_host=1,
    )
    app.config["SECRET_KEY"] = (
        secret_key if secret_key is not None
        else get_secret_key()
    )
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config.setdefault("CHAT_RATE_MAX", 10)
    app.config.setdefault("CHAT_RATE_WINDOW", 60)
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["PERMANENT_SESSION_LIFETIME"] = (
        timedelta(seconds=IDLE_TIMEOUT_SECONDS)
    )
    app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
    app.config["DEBUG"] = False
    app.config["TESTING"] = False
    app.config["PROPAGATE_EXCEPTIONS"] = False
    app.config["DB_PATH"] = str(db_path)
    app.config["MIGRATIONS_DIR"] = str(migrations_dir)
    app.config["AUDIT_BASE_DIR"] = audit_base_dir
    app.extensions["audit_writer"] = AuditWriter(
        base_dir=audit_base_dir,
    )

    if check_audit:
        expected_owner = pwd.getpwuid(os.getuid()).pw_name
        check_audit_logs(audit_base_dir, expected_owner)

    if check_schema:
        _conn = connect(app.config["DB_PATH"])
        try:
            check_schema_version(
                _conn, app.config["MIGRATIONS_DIR"],
            )
        finally:
            _conn.close()

    @app.before_request
    def _before():
        g.conn = connect(app.config["DB_PATH"])
        g.audit = app.extensions["audit_writer"]
        if is_public_path(request.path):
            return None
        view_fn = app.view_functions.get(request.endpoint)
        if view_fn is None or not hasattr(
            view_fn, "_required_permission",
        ):
            g.audit.log(
                agent="security_ai", tool="dashboard",
                policy_result="DENIED",
                permission_level=0,
                execution_status="FAILED",
                details={
                    "kind": "rbac_denied",
                    "route": request.endpoint,
                    "required_permission": "<none>",
                },
            )
            return ("Zugriff verweigert", 403)
        session_id = request.cookies.get(SESSION_COOKIE_NAME)
        sr = SessionRepository(g.conn)
        s = sr.get(session_id) if session_id else None
        if s is None or not s.is_active:
            return redirect("/login?next=" + request.path)
        now = datetime.now(UTC)
        try:
            last = datetime.fromisoformat(s.last_seen_at)
        except ValueError:
            sr.revoke(session_id, now=now)
            g.audit.log(
                agent="security_ai", tool="dashboard",
                policy_result="DENIED",
                permission_level=0,
                execution_status="FAILED",
                details={
                    "kind": "session_corrupt",
                    "principal": s.principal_name,
                },
            )
            return redirect("/login")
        if (now - last).total_seconds() > IDLE_TIMEOUT_SECONDS:
            sr.revoke(session_id, now=now)
            g.audit.log(
                agent="security_ai", tool="dashboard",
                policy_result="DENIED",
                permission_level=0,
                execution_status="FAILED",
                details={
                    "kind": "session_timeout",
                    "principal": s.principal_name,
                },
            )
            return redirect("/login")
        sr.touch(
            session_id,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            now=now,
        )
        g.principal = s.principal_name
        g.access_checker = AccessChecker.from_conn(g.conn)
        g.access_service = AccessService.from_conn(
            g.conn, g.audit,
        )
        g.access_checker.require_permission(
            g.principal, view_fn._required_permission,
        )
        return None

    @app.teardown_request
    def _teardown(exc):
        if hasattr(g, "conn") and g.conn is not None:
            try:
                g.conn.close()
            except Exception:
                pass

    @app.errorhandler(AccessDeniedError)
    def _denied(exc):
        return ("Zugriff verweigert", 403)

    @app.errorhandler(Exception)
    def _unhandled(exc):
        if isinstance(exc, HTTPException):
            return exc
        return (
            "Interner Fehler",
            500,
            {"Content-Type": "text/plain; charset=utf-8"},
        )

    from apps.dashboard.auth import register_auth_routes
    register_auth_routes(app)

    from apps.dashboard.routes_index import register_index_routes
    register_index_routes(app)

    from apps.dashboard.routes_inventory import register_inventory_routes
    register_inventory_routes(app)

    from apps.dashboard.routes_alerts import register_alerts_routes
    register_alerts_routes(app)

    from apps.dashboard.routes_approvals import register_approvals_routes
    register_approvals_routes(app)

    from apps.dashboard.routes_changes import register_changes_routes
    register_changes_routes(app)

    from apps.dashboard.routes_chat import register_chat_routes
    register_chat_routes(app)

    from apps.dashboard.routes_users import register_users_routes
    register_users_routes(app)

    from apps.dashboard.routes_roles import register_roles_routes
    register_roles_routes(app)

    from apps.dashboard.routes_audit import register_audit_routes
    register_audit_routes(app)

    from apps.dashboard.routes_settings import register_settings_routes
    register_settings_routes(app)

    from apps.dashboard.routes_search import register_search_routes
    register_search_routes(app)

    from apps.dashboard.filters import (
        format_score,
        format_score_label,
        format_source_label,
        format_ts,
    )
    app.add_template_filter(format_ts, "format_ts")
    app.add_template_filter(
        format_score_label, "format_score_label",
    )
    app.add_template_filter(format_score, "format_score")
    app.add_template_filter(
        format_source_label, "format_source_label",
    )

    @app.context_processor
    def _inject_nav_permissions():
        # 1. before_request setzt g.access_checker, g.principal
        # 2. context_processor liest sie (hier)
        # 3. after_request setzt Security-Header
        checker = getattr(g, "access_checker", None)
        principal = getattr(g, "principal", None)
        flags = {
            "can_view_dashboard": "device.read",
            "can_view_inventory": "device.read",
            "can_view_alerts": "alert.view",
            "can_view_approvals": "approval.view",
            "can_view_changes": "change.view",
            "can_view_chat": "chat.ask",
            "can_view_users": "principal.manage",
            "can_view_roles": "role.manage",
            "can_view_audit": "audit.read",
            "can_view_settings": "role.manage",
        }
        if checker is None or principal is None:
            return {k: False for k in flags}
        try:
            perms = checker.permissions_of(principal)
        except Exception:
            perms = frozenset()
        return {
            k: (code in perms) for k, code in flags.items()
        }

    @app.context_processor
    def _inject_csrf():
        # Token nur lesen oder anlegen (get_or_create ist
        # idempotent, kein Rotieren pro Request).
        from flask import session

        from apps.dashboard import csrf
        return {"csrf_token": csrf.get_or_create(session)}

    @app.after_request
    def _security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=(), "
            "payment=(), usb=(), interest-cohort=()"
        )
        return response

    return app


__all__ = [
    "create_app",
    "DEFAULT_AUDIT_DIR",
    "IDLE_TIMEOUT_SECONDS",
]

if __name__ == "__main__":
    # Lokaler Start fuer Entwicklung und systemd-Vorbereitung.
    # Kein threaded=True: der Dev-Server laeuft hinter nginx,
    # fuer Produktion waere gunicorn die richtige Wahl (eigene Runde).
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=False)
