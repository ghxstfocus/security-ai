"""
Tests fuer apps/dashboard/routes_changes.py.

Kategorie 3 (Route, RBAC, CSRF, Templates, Schreibpfad).

Auflagen 52-74 aus Review-Runde 3.6.8d.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from apps.dashboard import csrf
from core.changes.models import ChangeStatus
from core.changes.repository import (
    ChangeRepository,
    ChangeRepositoryError,
)
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


def _seed_change(app, *, title="Test", description="Desc",
                 change_type="config_change"):
    conn = connect(app.config["DB_PATH"])
    try:
        from core.changes.models import ChangeType
        return ChangeRepository(conn).create(
            title=title, description=description,
            requested_by="security_ai",
            type=ChangeType(change_type),
        ).change_id
    finally:
        conn.close()


def _get_change(app, change_id):
    conn = connect(app.config["DB_PATH"])
    try:
        return ChangeRepository(conn).get(change_id)
    finally:
        conn.close()


# --- RBAC ------------------------------------------------------------- #

def test_changes_without_session_redirects_to_login(app):
    c = app.test_client()
    r = c.get("/changes")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_changes_viewer_403(app):
    c = create_role_client(app, "viewer")
    r = c.get("/changes")
    assert r.status_code == 403


def test_changes_system_403(app):
    c = create_role_client(app, "system")
    r = c.get("/changes")
    assert r.status_code == 403


def test_changes_new_viewer_403(app):
    c = create_role_client(app, "viewer")
    r = c.get("/changes/new")
    assert r.status_code == 403


def test_changes_operator_lists_empty(app):
    c = create_role_client(app, "operator")
    r = c.get("/changes")
    assert r.status_code == 200
    assert "Keine Change Requests vorhanden".encode() in r.data


def test_changes_admin_lists_entry(app):
    cid = _seed_change(app, title="Firewall-Regel")
    c = create_role_client(app, "admin")
    r = c.get("/changes")
    assert r.status_code == 200
    assert cid.encode() in r.data
    assert b"Firewall-Regel" in r.data


# --- Detail ----------------------------------------------------------- #

def test_change_detail_shows_entry(app):
    cid = _seed_change(app, title="Detail-Titel")
    c = create_role_client(app, "admin")
    r = c.get("/changes/" + cid)
    assert r.status_code == 200
    assert cid.encode() in r.data
    assert b"Detail-Titel" in r.data


def test_change_detail_unknown_404(app):
    c = create_role_client(app, "admin")
    r = c.get("/changes/CHG-2099-99999")
    assert r.status_code == 404


@pytest.mark.parametrize("bad", [
    "CHG-2026-1", "CHG-26-00001", "chg-2026-00001",
    "CHG-2026-00001x", "..",
])
def test_change_detail_invalid_id_404(app, bad):
    c = create_role_client(app, "admin")
    r = c.get("/changes/" + bad)
    assert r.status_code == 404


def test_changes_unmatched_route_403_fail_closed(app):
    c = create_role_client(app, "admin")
    for path in ("/changes/", "/changes/x/y"):
        r = c.get(path)
        assert r.status_code == 403


# --- GET /changes/new ------------------------------------------------- #

def test_changes_new_form_operator_200(app):
    c = create_role_client(app, "operator")
    r = c.get("/changes/new")
    assert r.status_code == 200
    assert b'name="_csrf_token"' in r.data
    assert b'name="title"' in r.data
    assert b'name="type"' in r.data


# --- POST /changes/new: CSRF + Validierung ---------------------------- #

def _valid_form(tok, **kw):
    data = {
        "_csrf_token": tok,
        "title": "Test",
        "description": "Beschreibung",
        "type": "config_change",
    }
    data.update(kw)
    return data


def test_changes_new_without_csrf_400(app):
    c = create_role_client(app, "operator")
    r = c.post("/changes/new", data={
        "title": "x", "description": "y", "type": "config_change",
    })
    assert r.status_code == 400


def test_changes_new_wrong_csrf_400(app):
    c, _tok = _client_with_csrf(app, "operator")
    r = c.post("/changes/new", data={
        "_csrf_token": "falsch",
        "title": "x", "description": "y", "type": "config_change",
    })
    assert r.status_code == 400


def test_changes_new_invalid_type_400(app):
    c, tok = _client_with_csrf(app, "operator")
    r = c.post(
        "/changes/new",
        data=_valid_form(tok, type="nonsense"),
    )
    assert r.status_code == 400


def test_changes_new_missing_title_400(app):
    c, tok = _client_with_csrf(app, "operator")
    r = c.post("/changes/new", data={
        "_csrf_token": tok, "description": "y",
        "type": "config_change",
    })
    assert r.status_code == 400


def test_changes_new_title_too_long_400(app):
    c, tok = _client_with_csrf(app, "operator")
    r = c.post(
        "/changes/new",
        data=_valid_form(tok, title="x" * 201),
    )
    assert r.status_code == 400


def test_changes_new_description_too_long_400(app):
    c, tok = _client_with_csrf(app, "operator")
    r = c.post(
        "/changes/new",
        data=_valid_form(tok, description="x" * 2001),
    )
    assert r.status_code == 400


def test_changes_new_files_too_many_400(app):
    c, tok = _client_with_csrf(app, "operator")
    files = "\n".join(f"f{i}.txt" for i in range(51))
    r = c.post(
        "/changes/new",
        data=_valid_form(tok, files_affected=files),
    )
    assert r.status_code == 400


def test_changes_new_file_line_too_long_400(app):
    c, tok = _client_with_csrf(app, "operator")
    r = c.post(
        "/changes/new",
        data=_valid_form(tok, files_affected="x" * 501),
    )
    assert r.status_code == 400


# --- Happy Path ------------------------------------------------------- #

def test_changes_new_valid_creates_draft(app):
    c, tok = _client_with_csrf(app, "operator")
    r = c.post(
        "/changes/new",
        data=_valid_form(tok, title="Mein Change"),
    )
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/changes")
    conn = connect(app.config["DB_PATH"])
    try:
        rows = ChangeRepository(conn).list_all()
    finally:
        conn.close()
    assert len(rows) == 1
    assert rows[0].title == "Mein Change"
    assert rows[0].status is ChangeStatus.DRAFT
    assert rows[0].requested_by == "test-operator"


# --- XSS -------------------------------------------------------------- #

def test_changes_new_title_xss_escaped(app):
    c, tok = _client_with_csrf(app, "operator")
    payload = "<script>alert(1)</script>"
    c.post("/changes/new", data=_valid_form(tok, title=payload))
    r = c.get("/changes")
    assert r.status_code == 200
    assert b"<script>" not in r.data
    assert b"&lt;script&gt;" in r.data


def test_changes_detail_diff_xss_escaped(app):
    c, tok = _client_with_csrf(app, "operator")
    payload = "<script>alert(1)</script>"
    c.post(
        "/changes/new",
        data=_valid_form(tok, title="mit diff",
                          diff_or_patch=payload),
    )
    conn = connect(app.config["DB_PATH"])
    try:
        cid = ChangeRepository(conn).list_all()[0].change_id
    finally:
        conn.close()
    r = c.get("/changes/" + cid)
    assert r.status_code == 200
    assert b"<script>alert(1)</script>" not in r.data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in r.data


# --- CSP -------------------------------------------------------------- #

def test_changes_csp_header_present(app):
    c = create_role_client(app, "admin")
    r = c.get("/changes")
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp


# --- Auflage 60: Leak-Asserts ---------------------------------------- #

def _assert_no_leak(body: bytes) -> None:
    assert b"ChangeRepository" not in body
    assert b"changes_cli" not in body
    assert b"from core.changes" not in body
    assert b"from core.services" not in body
    assert b"change_service.py" not in body
    assert b"Traceback" not in body
    assert b"Traceback (most recent call last)" not in body
    assert b'  File "' not in body
    assert b"<script>" not in body


def test_no_leak_list(app):
    c = create_role_client(app, "admin")
    r = c.get("/changes")
    _assert_no_leak(r.data)


def test_no_leak_detail_404(app):
    c = create_role_client(app, "admin")
    r = c.get("/changes/CHG-2099-99999")
    _assert_no_leak(r.data)


def test_no_leak_post_xss_title(app):
    c, tok = _client_with_csrf(app, "operator")
    r = c.post(
        "/changes/new",
        data=_valid_form(tok, title="<script>alert(1)</script>"),
    )
    # 302-Body ist leer, aber sicher ist sicher.
    _assert_no_leak(r.data)


# --- Auflage 71: DB-Fehler -> 500 ------------------------------------ #

def test_changes_create_repo_error_500(app, monkeypatch):
    def _boom(*a, **kw):
        raise ChangeRepositoryError("simuliert")
    monkeypatch.setattr(
        ChangeRepository, "create", _boom,
    )
    c, tok = _client_with_csrf(app, "operator")
    r = c.post(
        "/changes/new",
        data=_valid_form(tok, title="db-fehler"),
    )
    assert r.status_code == 500
    assert b"simuliert" not in r.data
    _assert_no_leak(r.data)


# --- Auflage 72 + 73: Audit-Fehler -> 500, DB-Eintrag bleibt -------- #

def test_changes_create_audit_error_500_db_kept(app, monkeypatch):
    from harness.audit.writer import AuditWriter

    def _boom(self, *a, **kw):
        raise RuntimeError("audit kaputt")
    monkeypatch.setattr(AuditWriter, "log", _boom)
    c, tok = _client_with_csrf(app, "operator")
    r = c.post(
        "/changes/new",
        data=_valid_form(tok, title="audit-fehler"),
    )
    assert r.status_code == 500
    assert b"audit kaputt" not in r.data
    _assert_no_leak(r.data)
    # DB-Eintrag bleibt (Auflage 73):
    conn = connect(app.config["DB_PATH"])
    try:
        rows = ChangeRepository(conn).list_all()
    finally:
        conn.close()
    assert len(rows) == 1
    assert rows[0].title == "audit-fehler"
