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


# --- Punkt 19 (Auflagen 614-622): Pro-Tabelle-Klassen ------------- #

_TABELLEN = [
    ("/alerts", "table-alerts"),
    ("/approvals", "table-approvals"),
    ("/audit", "table-audit"),
    ("/changes", "table-changes"),
    ("/inventory", "table-inventory"),
    ("/users", "table-users"),
    ("/roles", "table-roles"),
]


def _seed_all_tables(app):
    """Fuellt die Test-DB und audit-logs, damit alle 7
    Listen-Seiten eine Tabelle rendern (Punkt 19, A618).
    """
    import json
    from datetime import datetime, timezone
    from pathlib import Path as _P
    from core.inventory.repository import connect

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    conn = connect(app.config["DB_PATH"])
    conn.execute(
        "INSERT INTO devices (identifier, entity_name, "
        "network_type, first_seen, last_seen) "
        "VALUES (?, ?, ?, ?, ?)",
        ("192.168.178.200", "test-device", "Hauptnetz",
         now_iso, now_iso),
    )
    conn.execute(
        "INSERT INTO approvals (request_id, timestamp, "
        "tool_name, args_json, requested_by, status, "
        "created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("APR-2099-00001", now_iso, "nmap_scan", "[]",
         "admin1", "pending", now_iso),
    )
    conn.execute(
        "INSERT INTO change_requests (change_id, timestamp, "
        "title, description, requested_by, status, type, "
        "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("CHG-2099-00001", now_iso, "Test-Change", "d",
         "admin1", "draft", "config_change", now_iso),
    )
    conn.commit()
    conn.close()

    audit_dir = _P(app.config["AUDIT_BASE_DIR"])
    audit_dir.mkdir(parents=True, exist_ok=True)
    day = now.strftime("%Y-%m-%d")
    f = audit_dir / f"{day}.jsonl"
    zeilen = [
        {
            "audit_id": "AUD-2099-01-01-00000001",
            "timestamp": now_iso,
            "agent": "security_ai",
            "tool": "chat_service",
            "policy_result": "ALLOWED",
            "permission_level": 0,
            "execution_status": "OK",
            "details": {"kind": "chat_query"},
        },
        {
            "audit_id": "AUD-2099-01-01-00000002",
            "timestamp": now_iso,
            "agent": "security_ai",
            "tool": "risk_engine",
            "policy_result": "ALLOWED",
            "permission_level": 0,
            "execution_status": "OK",
            "details": {
                "kind": "risk_assessment",
                "event_id": "EVT-2099-01-01-00000001",
                "category": "SUSPICION",
                "score": 0.5,
                "rule_id": "test_rule",
            },
        },
    ]
    f.write_text(
        "\n".join(json.dumps(z) for z in zeilen) + "\n",
        encoding="utf-8",
    )


def test_listen_seiten_haben_table_klassen(tmp_path):
    # A618: jede Listen-Seite traegt ihre table-<name>-Klasse.
    app = build_dashboard_app(tmp_path)
    _seed_all_tables(app)
    c = create_role_client(app, "admin")
    for route, klasse in _TABELLEN:
        r = c.get(route)
        assert r.status_code == 200, f"{route} -> {r.status_code}"
        assert f'class="table {klasse}"'.encode() in r.data, (
            f"{route} traegt {klasse} nicht"
        )


def test_components_css_hat_alle_klassen(tmp_path):
    # A617: Substring-Match fuer jede Klassen-Regel.
    c = _admin(tmp_path)
    r = c.get("/static/css/components.css")
    assert r.status_code == 200
    for _route, klasse in _TABELLEN:
        assert f"table.{klasse}".encode() in r.data, (
            f"{klasse} fehlt in components.css"
        )


def test_keine_globale_nth_child_regel(tmp_path):
    # A619: die alte globale nth-child(n+4)-Regel ist weg.
    c = _admin(tmp_path)
    r = c.get("/static/css/components.css")
    assert r.status_code == 200
    assert b".table th:nth-child(n+4)" not in r.data
    assert b".table td:nth-child(n+4)" not in r.data


# --- Topbar-Dropdown-JS (Auflagen 703-706, 745-750) ---------------- #

def test_user_menu_js_served(tmp_path):
    # A748: user_menu.js wird ausgeliefert.
    c = _admin(tmp_path)
    r = c.get("/static/js/user_menu.js")
    assert r.status_code == 200
    ct = r.headers.get("Content-Type", "")
    assert "javascript" in ct or "ecmascript" in ct
    assert b"addEventListener" in r.data
    assert b'"use strict"' in r.data


def test_user_menu_js_keine_verbotenen_patterns(tmp_path):
    # A748: kein innerHTML, kein onclick, kein eval.
    c = _admin(tmp_path)
    r = c.get("/static/js/user_menu.js")
    assert r.status_code == 200
    assert b"innerHTML" not in r.data
    assert b"onclick" not in r.data
    assert b"eval(" not in r.data


def test_user_menu_js_eingebunden_im_dashboard(tmp_path):
    # A746: base.html bindet user_menu.js ein.
    c = _admin(tmp_path)
    r = c.get("/")
    assert r.status_code == 200
    assert b"js/user_menu.js" in r.data


def test_user_menu_js_nicht_im_login(tmp_path):
    # A748: Login ist standalone, kein user_menu.js.
    c = _anon(tmp_path)
    r = c.get("/login")
    assert r.status_code == 200
    assert b"js/user_menu.js" not in r.data
