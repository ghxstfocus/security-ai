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

from datetime import datetime, timedelta, timezone

from flask import Flask, g, redirect, request
from werkzeug.exceptions import HTTPException

from core.access.checker import (
    AccessChecker, AccessDeniedError,
)
from core.access.session_repo import SessionRepository
from core.config import get_secret_key
from core.inventory.repository import (
    DEFAULT_DB_PATH,
    DEFAULT_MIGRATIONS_DIR,
    connect,
)
from core.services.access_service import AccessService
from harness.audit.writer import AuditWriter

from apps.dashboard.decorators import (
    SESSION_COOKIE_NAME,
    is_public_path,
)


DEFAULT_AUDIT_DIR = "audit-logs"
IDLE_TIMEOUT_SECONDS = 30 * 60


def create_app(
    *,
    db_path=DEFAULT_DB_PATH,
    migrations_dir=DEFAULT_MIGRATIONS_DIR,
    audit_base_dir: str = DEFAULT_AUDIT_DIR,
    secret_key: str | None = None,
) -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = (
        secret_key if secret_key is not None
        else get_secret_key()
    )
    app.config["SESSION_COOKIE_HTTPONLY"] = True
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
        now = datetime.now(timezone.utc)
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

    return app


__all__ = [
    "create_app",
    "DEFAULT_AUDIT_DIR",
    "IDLE_TIMEOUT_SECONDS",
]
