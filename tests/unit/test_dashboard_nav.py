"""Tests fuer 3.6.11 Hamburger-Navigation (Auflagen 357-360)."""

from tests.unit._helpers import build_dashboard_app, create_role_client


def _admin(tmp_path):
    app = build_dashboard_app(tmp_path)
    return create_role_client(app, "admin")


def _anon(tmp_path):
    app = build_dashboard_app(tmp_path)
    return app.test_client()


def test_nav_button_in_base(tmp_path):
    c = _admin(tmp_path)
    r = c.get("/")
    assert r.status_code == 200
    assert b'id="nav-toggle"' in r.data
    assert b'aria-controls="sidebar"' in r.data
    assert b'aria-expanded="false"' in r.data


def test_nav_login_no_button(tmp_path):
    c = _anon(tmp_path)
    r = c.get("/login")
    assert r.status_code == 200
    assert b'id="nav-toggle"' not in r.data


def test_nav_js_served(tmp_path):
    c = _admin(tmp_path)
    r = c.get("/static/js/nav.js")
    assert r.status_code == 200
    ct = r.headers.get("Content-Type", "")
    assert "javascript" in ct or "ecmascript" in ct
    assert b"addEventListener" in r.data
    assert b'"use strict"' in r.data
    assert b"eval(" not in r.data
    assert b"innerHTML" not in r.data


def test_no_inline_script_or_style(tmp_path):
    c = _admin(tmp_path)
    r = c.get("/alerts")
    assert r.status_code == 200
    assert b"<script>" not in r.data
    assert b'style="' not in r.data
    assert b"onclick=" not in r.data


def test_csp_header_unchanged_on_dashboard(tmp_path):
    c = _admin(tmp_path)
    for path in ["/", "/inventory", "/alerts", "/audit"]:
        r = c.get(path)
        csp = r.headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "unsafe-inline" not in csp
        assert "unsafe-eval" not in csp


# --- 3.6.16-topbar-usermenu (Auflagen 561-570) ---------------------- #

def test_user_menu_markup(tmp_path):
    c = _admin(tmp_path)
    r = c.get("/")
    assert r.status_code == 200
    assert b'<details class="user-menu">' in r.data
    assert b'<summary class="user-menu-summary">' in r.data


def test_user_menu_shows_person_icon(tmp_path):
    c = _admin(tmp_path)
    r = c.get("/")
    assert b"img/person.svg" in r.data


def test_logout_form_is_post(tmp_path):
    c = _admin(tmp_path)
    r = c.get("/")
    assert b'action="/logout"' in r.data
    assert b'method="post"' in r.data


def test_logout_form_has_csrf(tmp_path):
    c = _admin(tmp_path)
    r = c.get("/")
    assert b'name="_csrf_token"' in r.data


def test_user_menu_name_hidden_at_400px(tmp_path):
    c = _admin(tmp_path)
    r = c.get("/static/css/components.css")
    assert r.status_code == 200
    assert b"@media (max-width: 400px)" in r.data
    assert b".user-menu-name" in r.data


def test_user_menu_not_in_login(tmp_path):
    c = _anon(tmp_path)
    r = c.get("/login")
    assert r.status_code == 200
    assert b'<details class="user-menu">' not in r.data
