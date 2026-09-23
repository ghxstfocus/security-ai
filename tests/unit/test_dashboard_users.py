"""
Tests fuer apps/dashboard/routes_users.py.

Kategorie 3 (Route, RBAC, CSRF, Templates, principal_to_view,
MIN_PASSWORD_LEN).

Auflagen 143-178 aus Review-Runde 3.6.8f.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from apps.dashboard import csrf
from core.access.models import PrincipalKind
from core.inventory.repository import connect
from tests.unit._helpers import (
    build_dashboard_app,
    create_role_client,
)


@pytest.fixture()
def app(tmp_path: Path):
    return build_dashboard_app(tmp_path)


def _client_with_csrf(app, role):
    c = create_role_client(app, role)
    with c.session_transaction() as sess:
        tok = csrf.get_or_create(sess)
    return c, tok


def _audit_lines(app):
    base = Path(app.config["AUDIT_BASE_DIR"])
    out = []
    for p in sorted(base.glob("*.jsonl")):
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


# --- RBAC ------------------------------------------------------------- #

def test_users_without_session_redirects_to_login(app):
    c = app.test_client()
    r = c.get("/users")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_users_viewer_403(app):
    c = create_role_client(app, "viewer")
    r = c.get("/users")
    assert r.status_code == 403


def test_users_operator_403(app):
    c = create_role_client(app, "operator")
    r = c.get("/users")
    assert r.status_code == 403


def test_users_system_403(app):
    c = create_role_client(app, "system")
    r = c.get("/users")
    assert r.status_code == 403


def test_users_admin_lists(app):
    c = create_role_client(app, "admin")
    r = c.get("/users")
    assert r.status_code == 200
    assert b"Benutzer" in r.data


# --- Liste / Detail --------------------------------------------------- #

def test_users_list_shows_principals(app):
    c = create_role_client(app, "admin")
    r = c.get("/users")
    assert r.status_code == 200
    # admin1 + test-admin sind in der DB (build_dashboard_app
    # + create_role_client).
    assert b"admin1" in r.data


def test_users_detail_unknown_404(app):
    c = create_role_client(app, "admin")
    r = c.get("/users/gibtsnicht")
    assert r.status_code == 404


def test_users_detail_shows_entry(app):
    c = create_role_client(app, "admin")
    r = c.get("/users/admin1")
    assert r.status_code == 200
    assert b"admin1" in r.data


def test_users_list_has_no_password_hash(app):
    c = create_role_client(app, "admin")
    r = c.get("/users")
    assert b"password_hash" not in r.data
    assert b"pbkdf2" not in r.data
    assert b"$600000$" not in r.data


# --- POST /users/new: CSRF + Validierung ----------------------------- #

def _valid_new_form(tok, **kw):
    data = {
        "_csrf_token": tok,
        "name": "neu1",
        "role_name": "viewer",
        "kind": "human",
        "is_active": "on",
    }
    data.update(kw)
    return data


def test_new_without_csrf_400(app):
    c = create_role_client(app, "admin")
    r = c.post("/users/new", data={
        "name": "neu1", "role_name": "viewer", "kind": "human",
    })
    assert r.status_code == 400


def test_new_missing_name_400(app):
    c, tok = _client_with_csrf(app, "admin")
    r = c.post("/users/new", data=_valid_new_form(tok, name=""))
    assert r.status_code == 400


def test_new_unknown_role_400(app):
    c, tok = _client_with_csrf(app, "admin")
    r = c.post(
        "/users/new",
        data=_valid_new_form(tok, role_name="gibtsnicht"),
    )
    assert r.status_code == 400


def test_new_unknown_kind_400(app):
    c, tok = _client_with_csrf(app, "admin")
    r = c.post(
        "/users/new",
        data=_valid_new_form(tok, kind="alien"),
    )
    assert r.status_code == 400


def test_new_valid_without_password(app):
    c, tok = _client_with_csrf(app, "admin")
    r = c.post("/users/new", data=_valid_new_form(tok))
    assert r.status_code == 302
    conn = connect(app.config["DB_PATH"])
    try:
        row = conn.execute(
            "SELECT name, password_hash, is_active "
            "FROM principals WHERE name='neu1'"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row["password_hash"] is None
    assert row["is_active"] == 1


def test_new_with_short_password_400(app):
    c, tok = _client_with_csrf(app, "admin")
    r = c.post(
        "/users/new",
        data=_valid_new_form(tok, password="kurz1234"),
    )
    assert r.status_code == 400
    # Kein Principal angelegt (create_principal erst, dann
    # set_password schlaegt fehl -> DB-Eintrag bleibt).
    conn = connect(app.config["DB_PATH"])
    try:
        row = conn.execute(
            "SELECT password_hash FROM principals WHERE name='neu1'"
        ).fetchone()
    finally:
        conn.close()
    # create_principal lief, set_password nicht -> Eintrag ohne Hash.
    assert row is not None
    assert row["password_hash"] is None


def test_new_with_valid_password_302_hash_format(app):
    c, tok = _client_with_csrf(app, "admin")
    r = c.post(
        "/users/new",
        data=_valid_new_form(tok, password="geheim123456"),
    )
    assert r.status_code == 302
    conn = connect(app.config["DB_PATH"])
    try:
        row = conn.execute(
            "SELECT password_hash FROM principals WHERE name='neu1'"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row["password_hash"].startswith("pbkdf2_sha256$600000$")


def test_new_duplicate_400(app):
    c, tok = _client_with_csrf(app, "admin")
    # admin1 existiert bereits.
    r = c.post(
        "/users/new",
        data=_valid_new_form(tok, name="admin1"),
    )
    assert r.status_code == 400


# --- toggle-active ---------------------------------------------------- #

def test_toggle_without_csrf_400(app):
    c = create_role_client(app, "admin")
    r = c.post("/users/admin1/toggle-active", data={})
    assert r.status_code == 400


def test_toggle_active_value_flips(app):
    c, tok = _client_with_csrf(app, "admin")
    r = c.post(
        "/users/admin1/toggle-active",
        data={"_csrf_token": tok},
    )
    assert r.status_code == 302
    conn = connect(app.config["DB_PATH"])
    try:
        row = conn.execute(
            "SELECT is_active FROM principals WHERE name='admin1'"
        ).fetchone()
    finally:
        conn.close()
    assert row["is_active"] == 0


def test_self_deactivate_400(app):
    c, tok = _client_with_csrf(app, "admin")
    # test-admin (create_role_client) ist der eingeloggte
    # Principal; er darf sich nicht selbst deaktivieren.
    r = c.post(
        "/users/test-admin/toggle-active",
        data={"_csrf_token": tok},
    )
    assert r.status_code == 400


# --- set-password ----------------------------------------------------- #

def test_set_password_without_csrf_400(app):
    c = create_role_client(app, "admin")
    r = c.post(
        "/users/admin1/set-password",
        data={"password": "geheim123456"},
    )
    assert r.status_code == 400


def test_set_password_too_short_400(app):
    c, tok = _client_with_csrf(app, "admin")
    r = c.post(
        "/users/admin1/set-password",
        data={"_csrf_token": tok, "password": "kurz1234"},
    )
    assert r.status_code == 400


def test_set_password_valid_hash(app):
    c, tok = _client_with_csrf(app, "admin")
    r = c.post(
        "/users/admin1/set-password",
        data={"_csrf_token": tok, "password": "geheim123456"},
    )
    assert r.status_code == 302
    conn = connect(app.config["DB_PATH"])
    try:
        row = conn.execute(
            "SELECT password_hash FROM principals "
            "WHERE name='admin1'"
        ).fetchone()
    finally:
        conn.close()
    assert row["password_hash"].startswith("pbkdf2_sha256$600000$")


# --- A157: set_password invalidiert Sessions ------------------------- #

def test_set_password_revokes_sessions(app):
    # admin legt den Principal an und bekommt eine eigene
    # Session.
    admin_c, admin_tok = _client_with_csrf(app, "admin")
    admin_c.post("/users/new", data={
        "_csrf_token": admin_tok,
        "name": "opfer",
        "role_name": "viewer",
        "kind": "human",
        "is_active": "on",
        "password": "geheim123456",
    })
    # opfer bekommt eine Session (Principal existiert bereits,
    # nur Session anlegen).
    from core.access.session_repo import SessionRepository
    from tests.unit._helpers import set_session_cookie
    conn = connect(app.config["DB_PATH"])
    try:
        SessionRepository(conn).create("sid-opfer", "opfer")
    finally:
        conn.close()
    opfer = app.test_client()
    set_session_cookie(opfer, "sid-opfer")
    r = opfer.get("/")
    assert r.status_code == 200
    # admin setzt neues Passwort fuer opfer.
    r = admin_c.post(
        "/users/opfer/set-password",
        data={"_csrf_token": admin_tok,
              "password": "neuespasswort1"},
    )
    assert r.status_code == 302
    # opfer-Session muss invalidiert sein.
    r = opfer.get("/")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


# --- A165: kein Passwort im Audit ------------------------------------ #

def test_new_password_not_in_audit(app):
    c, tok = _client_with_csrf(app, "admin")
    password = "einzigartigespasswort123"
    c.post(
        "/users/new",
        data=_valid_new_form(tok, name="audittest", password=password),
    )
    for entry in _audit_lines(app):
        blob = json.dumps(entry)
        assert password not in blob
        assert "pbkdf2" not in blob


# --- A164: Leak-Asserts ---------------------------------------------- #

def _assert_no_leak(body: bytes) -> None:
    for marker in (
        b"password_hash", b"pbkdf2", b"$600000$",
        b"AccessService", b"SessionRepository",
        b"principal_to_view", b"Traceback", b'  File "',
    ):
        assert marker not in body, f"Leak: {marker!r}"


def test_no_leak_list(app):
    c = create_role_client(app, "admin")
    r = c.get("/users")
    _assert_no_leak(r.data)


def test_no_leak_detail(app):
    c = create_role_client(app, "admin")
    r = c.get("/users/admin1")
    _assert_no_leak(r.data)


def test_no_leak_new_form(app):
    c = create_role_client(app, "admin")
    r = c.get("/users/new")
    _assert_no_leak(r.data)
