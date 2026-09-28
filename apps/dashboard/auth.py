"""
Login, Logout, whoami fuer das Dashboard.

Kategorie 3 (RBAC, Session, CSRF, Audit).

Auflagen 115-167.
"""
from __future__ import annotations

import secrets
import urllib.parse as _urlparse
from enum import Enum

from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
)

from apps.dashboard import csrf
from apps.dashboard.decorators import (
    SESSION_COOKIE_NAME,
    require_permission,
)
from core.access.models import (
    hash_password,
    verify_password,
)
from core.access.repository import (
    AccessNotFoundError,
    PrincipalRepository,
)
from core.access.session_repo import (
    LoginAttemptRepository,
    SessionRepository,
)

LOGIN_MAX_FAILURES = 5
LOGIN_HARD_LIMIT = 20
LOGIN_WINDOW_SECONDS = 900
IDLE_TIMEOUT_SECONDS = 30 * 60


_DUMMY_HASH: str | None = None


def _get_dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(
            secrets.token_urlsafe(32),
        )
    return _DUMMY_HASH


class RateLimitResult(str, Enum):
    OK = "ok"
    LOCKED = "locked"
    HARD = "hard"


def _ua() -> str:
    return (request.headers.get("User-Agent") or "")[:200]


def _details(kind: str, principal):
    return {
        "kind": kind,
        "principal": principal if principal else None,
        "ip": request.remote_addr,
        "user_agent": _ua(),
    }


def _audit(kind: str, policy: str, status: str, principal):
    g.audit.log(
        agent="security_ai", tool="dashboard",
        policy_result=policy, permission_level=0,
        execution_status=status,
        details=_details(kind, principal),
    )


def _check_rate_limit(ip, repo, app) -> RateLimitResult:
    max_f = app.config.get(
        "LOGIN_MAX_FAILURES", LOGIN_MAX_FAILURES,
    )
    hard = app.config.get(
        "LOGIN_HARD_LIMIT", LOGIN_HARD_LIMIT,
    )
    n = repo.count_recent_failures(
        ip, window_seconds=LOGIN_WINDOW_SECONDS,
    )
    if n >= hard:
        return RateLimitResult.HARD
    if n >= max_f:
        return RateLimitResult.LOCKED
    return RateLimitResult.OK


def _safe_next(raw) -> str:
    if not raw or not isinstance(raw, str):
        return "/"
    decoded = _urlparse.unquote(raw)
    if not decoded.startswith("/"):
        return "/"
    if decoded.startswith("//"):
        return "/"
    if decoded.startswith("/\\"):
        return "/"
    if any(c in decoded for c in ("\r", "\n", "\x00")):
        return "/"
    return decoded


def register_auth_routes(app: Flask) -> None:
    @app.route("/login", methods=["GET"])
    def login_form():
        token = csrf.get_or_create(session)
        nxt = _safe_next(request.args.get("next"))
        return render_template(
            "login.html",
            token=token,
            next_path=nxt,
        )

    @app.route("/login", methods=["POST"])
    def login_post():
        # 1. CSRF
        submitted = request.form.get("_csrf_token")
        expected = session.get("_csrf_token")
        if not csrf.validate(submitted, expected):
            return ("Ungueltige Anfrage", 400)
        # 2. Pflicht-Felder
        name = request.form.get("principal")
        password = request.form.get("password")
        if not name or not password:
            return ("Ungueltige Anfrage", 400)
        # 3. Rate-Limit
        attempts = LoginAttemptRepository(g.conn)
        ip = request.remote_addr or "unknown"
        r = _check_rate_limit(ip, attempts, app)
        if r == RateLimitResult.HARD:
            _audit("login_locked", "DENIED", "FAILED", name)
            return ("Zu viele Anfragen", 429)
        if r == RateLimitResult.LOCKED:
            _audit("login_locked", "DENIED", "FAILED", name)
            return ("Ungueltige Anmeldedaten", 401)
        # 4. Principal
        principals = PrincipalRepository(g.conn)
        try:
            p = principals.get_by_name(name)
        except AccessNotFoundError:
            verify_password(password, _get_dummy_hash())
            attempts.record(
                ip=ip, principal_name=name, success=False,
            )
            _audit("login_failed", "DENIED", "FAILED", name)
            return ("Ungueltige Anmeldedaten", 401)
        # 5. is_active
        if not p.is_active:
            verify_password(password, _get_dummy_hash())
            attempts.record(
                ip=ip, principal_name=name, success=False,
            )
            _audit("login_locked", "DENIED", "FAILED", name)
            return ("Ungueltige Anmeldedaten", 401)
        # 6. verify_password
        stored = p.password_hash
        if not stored:
            verify_password(password, _get_dummy_hash())
            attempts.record(
                ip=ip, principal_name=name, success=False,
            )
            _audit("login_failed", "DENIED", "FAILED", name)
            return ("Ungueltige Anmeldedaten", 401)
        if not verify_password(password, stored):
            attempts.record(
                ip=ip, principal_name=name, success=False,
            )
            _audit("login_failed", "DENIED", "FAILED", name)
            return ("Ungueltige Anmeldedaten", 401)
        # 7. Alte Session revoken
        sr = SessionRepository(g.conn)
        old_id = request.cookies.get(SESSION_COOKIE_NAME)
        if old_id:
            sr.revoke(old_id)
        # 8. Neue Session
        new_id = secrets.token_urlsafe(32)
        sr.create(new_id, p.name, ip=ip, user_agent=_ua())
        # 9. CSRF rotieren
        csrf.rotate(session)
        # 10. Audit
        attempts.record(
            ip=ip, principal_name=name, success=True,
        )
        _audit("login_success", "ALLOWED", "OK", p.name)
        # 11-12. Cookie + Redirect
        next_path = _safe_next(request.form.get("next"))
        resp = redirect(next_path, 302)
        resp.set_cookie(
            SESSION_COOKIE_NAME, new_id,
            max_age=IDLE_TIMEOUT_SECONDS, path="/",
            secure=True, httponly=True, samesite="Strict",
        )
        return resp

    @app.route("/logout", methods=["POST"])
    @require_permission("chat.ask")
    def logout_post():
        submitted = request.form.get("_csrf_token")
        expected = session.get("_csrf_token")
        if not csrf.validate(submitted, expected):
            return ("Ungueltige Anfrage", 400)
        sid = request.cookies.get(SESSION_COOKIE_NAME)
        if sid:
            sr = SessionRepository(g.conn)
            sr.revoke(sid)
            _audit("logout", "ALLOWED", "OK",
                   getattr(g, "principal", None))
        resp = redirect("/login", 302)
        resp.delete_cookie(SESSION_COOKIE_NAME, path="/")
        return resp

    @app.route("/whoami", methods=["GET"])
    @require_permission("chat.ask")
    def whoami_get():
        me = g.access_service.whoami(g.principal)
        return jsonify(me)


__all__ = ["register_auth_routes", "RateLimitResult"]
