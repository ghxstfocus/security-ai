"""
Tests fuer apps/dashboard/app.py.

Kategorie 3 (RBAC, Session, Fehlerbehandlung).

Auflage 67: TESTING bleibt False. Wir testen
Produktions-Verhalten (generische 500).
Auflage 68: Cookie-Flags explizit (secure, httponly,
samesite).
Auflage 71: test_access_denied_errorhandler_403 loest
echten 403 aus (viewer ohne principal.manage).
Auflage 72: test_two_requests_ok_after_teardown
(statt "conn geschlossen"-Pseudotest).
Auflage 73: Sicherheitsnetz-Tests umbenannt
(_mit_session / _ohne_session).
Auflage 74: test_alle_routen_haben_permission
zaehlt geprueft.
Auflage 106: Test 12 bleibt leer-tolerant, neuer
Test 13 prueft den Mechanismus.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from apps.dashboard.app import create_app
from apps.dashboard.decorators import (
    PUBLIC_PATHS,
    require_permission,
)
from core.access.session_repo import SessionRepository
from core.inventory.repository import (
    DEFAULT_MIGRATIONS_DIR,
    SchemaVersionError,
    connect,
)
from tests.unit._helpers import (
    build_dashboard_app,
    create_role_client,
    set_session_cookie,
)


@pytest.fixture()
def app(tmp_path: Path):
    return build_dashboard_app(tmp_path)


@pytest.fixture()
def client(app):
    c = app.test_client()
    set_session_cookie(c, "sid-1")
    return c


@pytest.fixture()
def viewer_client(app):
    c = app.test_client()
    set_session_cookie(c, "sid-viewer")
    return c


# ---------------------------------------------------------------------- #
# Tests 1-4
# ---------------------------------------------------------------------- #

def test_public_paths_has_login():
    assert "/login" in PUBLIC_PATHS


def test_create_app_registers_before_request(app):
    assert app.before_request_funcs


def test_require_permission_sets_attribute():
    def fn():
        return "ok"
    wrapped = require_permission("device.read")(fn)
    assert wrapped._required_permission == "device.read"


def test_route_without_permission_returns_403_mit_session(
    app, client,
):
    @app.route("/noperm1")
    def _leak1():
        return "should not happen"
    r = client.get("/noperm1")
    assert r.status_code == 403
    assert b"should not happen" not in r.data


# ---------------------------------------------------------------------- #
# Tests 5-8
# ---------------------------------------------------------------------- #

def test_route_without_permission_returns_403_ohne_session(app):
    @app.route("/noperm2")
    def _leak2():
        return "should not happen"
    c = app.test_client()
    r = c.get("/noperm2")
    assert r.status_code == 403
    assert b"should not happen" not in r.data


def test_route_with_permission_ok(app, client):
    @app.route("/ok")
    @require_permission("device.read")
    def _ok():
        return "ok", 200
    r = client.get("/ok")
    assert r.status_code == 200
    assert r.data == b"ok"


def test_login_form_renders_csrf_input(app):
    # Auflage 168: echte /login-Route (kein
    # Test-Override). Prueft CSRF-Input.
    c = app.test_client()
    r = c.get("/login")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith(
        "text/html",
    )
    assert b'action="/login"' in r.data
    assert b'name="_csrf_token"' in r.data


def test_no_session_redirects_to_login(app):
    @app.route("/secret")
    @require_permission("device.read")
    def _secret():
        return "secret", 200
    c = app.test_client()
    r = c.get("/secret")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


# ---------------------------------------------------------------------- #
# Tests 9-13
# ---------------------------------------------------------------------- #

def test_two_requests_ok_after_teardown(app, client):
    @app.route("/twice")
    @require_permission("device.read")
    def _twice():
        return "x", 200
    r1 = client.get("/twice")
    r2 = client.get("/twice")
    assert r1.status_code == 200
    assert r2.status_code == 200


def test_access_denied_errorhandler_403(app, viewer_client):
    @app.route("/need-admin")
    @require_permission("principal.manage")
    def _need_admin():
        return "should not happen"
    r = viewer_client.get("/need-admin")
    assert r.status_code == 403
    assert b"should not happen" not in r.data


def test_500_errorhandler_generisch(app, client):
    @app.route("/boom")
    @require_permission("device.read")
    def _boom():
        raise RuntimeError("interner Fehler")
    r = client.get("/boom")
    assert r.status_code == 500
    assert b"interner Fehler" not in r.data


def test_alle_routen_haben_permission(app):
    # Auflage 106: leer-tolerant heute. Ab 3.6.6 mit
    # produktiven Routen wird dieser Test wertvoll.
    geprueft = 0
    for rule in app.url_map.iter_rules():
        path = rule.rule
        if path in PUBLIC_PATHS:
            continue
        if path.startswith("/static/"):
            continue
        fn = app.view_functions.get(rule.endpoint)
        assert hasattr(fn, "_required_permission"), (
            f"Route {rule.endpoint} ({path}) ohne "
            f"@require_permission"
        )
        geprueft += 1


def test_alle_routen_mechanismus_mit_dekorierter_route(app):
    # Auflage 106: Mechanismus mit eigener Route.
    @app.route("/dekoriert")
    @require_permission("device.read")
    def _d():
        return "d", 200
    geprueft = 0
    for rule in app.url_map.iter_rules():
        if rule.rule in PUBLIC_PATHS:
            continue
        if rule.rule.startswith("/static/"):
            continue
        fn = app.view_functions.get(rule.endpoint)
        assert hasattr(fn, "_required_permission")
        geprueft += 1
    assert geprueft >= 1


# ---------------------------------------------------------------------- #
# Tests 3.6.7b: CSP + Security-Header + XSS
# ---------------------------------------------------------------------- #

def test_csp_header_present(app):
    # Auflage 252: /login liefert HTML-Response.
    c = app.test_client()
    r = c.get("/login")
    assert r.status_code == 200
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "object-src 'none'" in csp
    # Auflage 228: kein unsafe-inline
    assert "unsafe-inline" not in csp


def test_security_headers_present(app):
    c = app.test_client()
    r = c.get("/login")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("Referrer-Policy") == "same-origin"
    perms = r.headers.get("Permissions-Policy", "")
    assert "geolocation=()" in perms
    assert "camera=()" in perms
    assert "microphone=()" in perms


def test_csp_header_on_500(app, client):
    @app.route("/boom_csp")
    @require_permission("device.read")
    def _boom_csp():
        raise RuntimeError("test")
    r = client.get("/boom_csp")
    assert r.status_code == 500
    assert "Content-Security-Policy" in r.headers


def test_login_form_escapes_next_param_ok_prefix(app):
    c = app.test_client()
    r = c.get(
        "/login?next=/foo<script>alert(1)</script>",
    )
    assert r.status_code == 200
    assert b"<script>" not in r.data
    assert b"&lt;script&gt;" in r.data


def test_login_form_reduces_next_to_slash_on_no_slash(app):
    c = app.test_client()
    r = c.get(
        "/login?next=<script>alert(1)</script>",
    )
    assert r.status_code == 200
    assert b"<script>" not in r.data
    assert b'name="next"' in r.data
    assert b'value="/"' in r.data


# ---------------------------------------------------------------------- #
# Tests 3.6.7d: Index-Seite
# ---------------------------------------------------------------------- #

def test_index_renders_200(app, client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"dashboard-grid" in r.data


def test_csp_header_on_index(app, client):
    r = client.get("/")
    csp = r.headers.get("Content-Security-Policy", "")
    assert csp
    assert "'unsafe-inline'" not in csp
    assert "default-src 'self'" in csp


def test_index_requires_session(app):
    c = app.test_client()
    r = c.get("/")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_index_contains_stat_cards(app, client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.data.count(b"card-label") >= 4


# ---------------------------------------------------------------------- #
# Test 3.6.7e: CSP alle Direktiven
# ---------------------------------------------------------------------- #

def test_csp_all_directives_present(app):
    c = app.test_client()
    r = c.get("/login")
    csp = r.headers.get("Content-Security-Policy", "")
    assert csp, "CSP-Header fehlt"
    for directive in (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
    ):
        assert directive in csp, f"{directive} fehlt"
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


# ---------------------------------------------------------------------- #
# Tests 3.6.8: Bedingte Sidebar + Stat-Cards
# ---------------------------------------------------------------------- #

def test_index_admin_sees_alerts_card(app, client):
    r = client.get("/")
    assert b'data-card="alerts"' in r.data


def test_index_viewer_does_not_see_alerts_card(
    app, viewer_client,
):
    r = viewer_client.get("/")
    assert b'data-card="alerts"' not in r.data


@pytest.mark.parametrize(
    "role,slug,visible",
    [
        ("admin", "alerts", True),
        ("operator", "alerts", True),
        ("viewer", "alerts", False),
        ("admin", "users", True),
        ("operator", "users", False),
        ("viewer", "users", False),
        ("admin", "audit", True),
        ("viewer", "audit", True),
    ],
)
def test_sidebar_visibility(app, role, slug, visible):
    tmp_name = f"t-{role}-{slug}"
    c = create_role_client(app, role, tmp_name=tmp_name)
    r = c.get("/")
    body = r.data
    needle = ('data-nav="' + slug + '"').encode()
    assert (needle in body) == visible


# ---------------------------------------------------------------------- #
# Tests 3.6.15a Fix D: Schema-Versions-Check in create_app
# ---------------------------------------------------------------------- #

def test_create_app_check_schema_true_fails(tmp_path):
    # Auflage 408: frische DB, keine Migrationen,
    # check_schema=True -> SchemaVersionError mit
    # diagnostischer Message (Auflage 403).
    db = tmp_path / "fresh.db"
    with pytest.raises(
        SchemaVersionError, match="schema_migrations fehlt",
    ):
        create_app(
            check_schema=True,
            db_path=db,
            migrations_dir=DEFAULT_MIGRATIONS_DIR,
            audit_base_dir=str(tmp_path / "audit"),
            secret_key="x" * 48,
        )


def test_create_app_check_schema_false_ok(tmp_path):
    # check_schema=False: App wird auch ohne
    # Migrationen gebaut (Testhelfer-Pfad).
    db = tmp_path / "fresh2.db"
    app = create_app(
        check_schema=False,
        db_path=db,
        migrations_dir=DEFAULT_MIGRATIONS_DIR,
        audit_base_dir=str(tmp_path / "audit"),
        secret_key="x" * 48,
    )
    assert app is not None
    assert app.config["DB_PATH"] == str(db)


# ---------------------------------------------------------------------- #
# Kacheln mit Live-Werten (A7/A8, Block Kacheln)
# ---------------------------------------------------------------------- #

def test_index_viewer_sees_only_devices_card(
    app, viewer_client,
):
    """viewer hat nur device.read -> nur Geraete-Kachel."""
    r = viewer_client.get("/")
    assert r.status_code == 200
    assert b'data-card="devices"' in r.data
    assert b'data-card="alerts"' not in r.data
    assert b'data-card="approvals"' not in r.data
    assert b'data-card="changes"' not in r.data


def test_index_admin_sees_all_four_cards(
    app, client,
):
    """admin hat alle vier Permissions -> vier Kacheln."""
    r = client.get("/")
    assert r.status_code == 200
    for slug in (b"devices", b"alerts", b"approvals", b"changes"):
        assert b'data-card="' + slug + b'"' in r.data


def test_index_cards_show_live_value_not_dash(
    app, client,
):
    """
    Admin-Client mit leerer Test-DB:
    Kachel-Werte sind 0 (Zahl), nicht "—" (em-dash).
    Der em-dash waere das Zeichen fuer Service-Fehler
    oder fehlende Permission.
    """
    r = client.get("/")
    assert r.status_code == 200
    # Nur den Kachel-Bereich pruefen: seit T1+T5 gibt
    # es ausserhalb der Kacheln legitime em-dash-
    # Platzhalter (live-timestamp).
    start = r.data.find(b'<div class="stat-cards">')
    assert start >= 0
    end = r.data.find(b'</div>', start)
    assert end > start
    kacheln = r.data[start:end]
    # card-value-Block: nach dem Aufruf enthaelt jede
    # Kachel eine Zahl oder "—". Wir erwarten KEIN
    # em-dash fuer admin (leere DB = 0).
    assert b"\xe2\x80\x94" not in kacheln


# ---------------------------------------------------------------------- #
# B1a: Session-Guards + safe_redirect (Kategorie 3)
# ---------------------------------------------------------------------- #

def test_safe_redirect_returns_302_and_location():
    """safe_redirect() liefert 302 + Location.

    Der cast() im Helper ist ein Typ-Hint fuer mypy,
    aendert aber zur Laufzeit nichts: redirect()
    liefert weiterhin werkzeug.Response, das
    Flask als Response akzeptiert. Der Test prueft
    die Laufzeit-Garantie, nicht die mypy-Sicht.
    """
    from apps.dashboard._redirect import safe_redirect

    r = safe_redirect("/login")
    assert r.status_code == 302
    assert r.headers["Location"] == "/login"


def test_safe_redirect_custom_code():
    from apps.dashboard._redirect import safe_redirect

    r = safe_redirect("/x", code=303)
    assert r.status_code == 303
    assert r.headers["Location"] == "/x"


def test_before_inactive_session_redirects(app):
    """Session mit revoked_at -> Redirect auf /login."""
    from datetime import UTC, datetime

    conn = connect(app.config["DB_PATH"])
    sr = SessionRepository(conn)
    sr.revoke("sid-1", now=datetime.now(UTC))
    conn.close()

    c = app.test_client()
    set_session_cookie(c, "sid-1")
    r = c.get("/")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_before_session_timeout_redirects(app):
    """Idle-Timeout: last_seen_at > IDLE_TIMEOUT_SECONDS
    -> Redirect auf /login."""
    from datetime import UTC, datetime, timedelta

    from apps.dashboard.app import IDLE_TIMEOUT_SECONDS

    conn = connect(app.config["DB_PATH"])
    sr = SessionRepository(conn)
    stale = datetime.now(UTC) - timedelta(
        seconds=IDLE_TIMEOUT_SECONDS + 60,
    )
    sr.touch("sid-1", now=stale)
    conn.close()

    c = app.test_client()
    set_session_cookie(c, "sid-1")
    r = c.get("/")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]

def test_index_shows_network_cards(app, client):
    """T3 (Auflage 1692): / enthaelt Hauptnetz- und
    Gastnetz-Kachel mit data_card."""
    r = client.get("/")
    assert r.status_code == 200
    assert b'data-card="network-hauptnetz"' in r.data
    assert b'data-card="network-gastnetz"' in r.data

def test_index_cards_are_links(app, client):
    """T6 (Auflage 1683): Kacheln sind <a class="card-link">."""
    r = client.get("/")
    assert r.status_code == 200
    assert b'class="card card-accent-cyan card-link"' in r.data
    assert b'href="/inventory"' in r.data
    assert b'href="/alerts"' in r.data
    assert b'href="/approvals"' in r.data
    assert b'href="/changes"' in r.data


def test_index_shows_extern_card(app, client):
    """Punkt 65: Extern-Kachel im HTML."""
    r = client.get("/")
    assert r.status_code == 200
    assert b'data-card="network-extern"' in r.data
