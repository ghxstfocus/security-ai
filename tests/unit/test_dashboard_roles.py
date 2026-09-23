"""
Tests fuer apps/dashboard/routes_roles.py.

Kategorie 3 (Route, RBAC, CSRF, Templates, role_to_view,
permission_to_view).

Auflagen 179-189 aus Review-Runde 3.6.8g.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from apps.dashboard import csrf
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


def _has_perm(app, role_name, code):
    conn = connect(app.config["DB_PATH"])
    try:
        row = conn.execute(
            "SELECT 1 FROM role_permissions rp "
            "JOIN roles r ON r.id = rp.role_id "
            "JOIN permissions p ON p.id = rp.permission_id "
            "WHERE r.name = ? AND p.code = ?",
            (role_name, code),
        ).fetchone()
    finally:
        conn.close()
    return row is not None


# --- RBAC ------------------------------------------------------------- #

def test_roles_without_session_redirects_to_login(app):
    c = app.test_client()
    r = c.get("/roles")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_roles_viewer_403(app):
    c = create_role_client(app, "viewer")
    r = c.get("/roles")
    assert r.status_code == 403


def test_roles_operator_403(app):
    c = create_role_client(app, "operator")
    r = c.get("/roles")
    assert r.status_code == 403


def test_roles_system_403(app):
    c = create_role_client(app, "system")
    r = c.get("/roles")
    assert r.status_code == 403


def test_roles_admin_lists(app):
    c = create_role_client(app, "admin")
    r = c.get("/roles")
    assert r.status_code == 200
    assert b"admin" in r.data
    assert b"viewer" in r.data


# --- Detail ----------------------------------------------------------- #

def test_roles_detail_unknown_404(app):
    c = create_role_client(app, "admin")
    r = c.get("/roles/gibtsnicht")
    assert r.status_code == 404


@pytest.mark.parametrize("bad", [
    "mit space",
    "mit.punkt",
    "a" * 65,
    "ä",
])
def test_roles_detail_invalid_name_404(app, bad):
    c = create_role_client(app, "admin")
    r = c.get("/roles/" + bad)
    assert r.status_code == 404


def test_roles_unmatched_route_403_fail_closed(app):
    c = create_role_client(app, "admin")
    for path in ("/roles/", "/roles/a/b"):
        r = c.get(path)
        assert r.status_code == 403


def test_roles_detail_shows_admin(app):
    c = create_role_client(app, "admin")
    r = c.get("/roles/admin")
    assert r.status_code == 200
    assert b"admin" in r.data
    # admin hat alle Permissions; eine muss sichtbar sein.
    assert b"role.manage" in r.data


def test_roles_detail_permissions_sorted(app):
    c = create_role_client(app, "admin")
    r = c.get("/roles/admin")
    body = r.data.decode("utf-8", errors="replace")
    # Die Permissions erscheinen in der Reihenfolge
    # sortiert. Test: erste vorkommende bekannte Permission
    # ist alphabetisch vor der naechsten.
    codes = [
        "approval.decide", "approval.view",
        "audit.read", "audit.write",
        "change.create", "change.decide", "change.deploy",
        "change.view",
    ]
    positions = []
    for c in codes:
        idx = body.find(c)
        if idx != -1:
            positions.append((idx, c))
    positions.sort()
    assert [c for _i, c in positions] == sorted(
        c for _i, c in positions
    )


# --- POST assign-permission ------------------------------------------ #

def test_assign_without_csrf_400(app):
    c = create_role_client(app, "admin")
    r = c.post(
        "/roles/viewer/assign-permission",
        data={"permission_code": "device.write"},
    )
    assert r.status_code == 400


def test_assign_unknown_permission_404(app):
    c, tok = _client_with_csrf(app, "admin")
    r = c.post(
        "/roles/viewer/assign-permission",
        data={"_csrf_token": tok,
              "permission_code": "gibtsnicht.code"},
    )
    assert r.status_code == 404


def test_assign_invalid_permission_code_400(app):
    c, tok = _client_with_csrf(app, "admin")
    r = c.post(
        "/roles/viewer/assign-permission",
        data={"_csrf_token": tok,
              "permission_code": "mit leerzeichen"},
    )
    assert r.status_code == 400


def test_assign_valid_302_and_db(app):
    assert not _has_perm(app, "viewer", "device.write")
    c, tok = _client_with_csrf(app, "admin")
    r = c.post(
        "/roles/viewer/assign-permission",
        data={"_csrf_token": tok,
              "permission_code": "device.write"},
    )
    assert r.status_code == 302
    assert _has_perm(app, "viewer", "device.write")


def test_assign_idempotent(app):
    c, tok = _client_with_csrf(app, "admin")
    for _ in range(2):
        r = c.post(
            "/roles/viewer/assign-permission",
            data={"_csrf_token": tok,
                  "permission_code": "device.write"},
        )
        assert r.status_code == 302
    assert _has_perm(app, "viewer", "device.write")


# --- POST revoke-permission ------------------------------------------ #

def test_revoke_without_csrf_400(app):
    c = create_role_client(app, "admin")
    r = c.post(
        "/roles/viewer/revoke-permission",
        data={"permission_code": "device.read"},
    )
    assert r.status_code == 400


def test_revoke_valid_302_and_db(app):
    # viewer hat device.read (Migration 0005).
    assert _has_perm(app, "viewer", "device.read")
    c, tok = _client_with_csrf(app, "admin")
    r = c.post(
        "/roles/viewer/revoke-permission",
        data={"_csrf_token": tok,
              "permission_code": "device.read"},
    )
    assert r.status_code == 302
    assert not _has_perm(app, "viewer", "device.read")


def test_revoke_not_assigned_still_302(app):
    """Revoke einer nicht zugewiesenen Permission -> 302."""
    c, tok = _client_with_csrf(app, "admin")
    r = c.post(
        "/roles/viewer/revoke-permission",
        data={"_csrf_token": tok,
              "permission_code": "change.deploy"},
    )
    assert r.status_code == 302


def test_revoke_invalid_code_400(app):
    c, tok = _client_with_csrf(app, "admin")
    r = c.post(
        "/roles/viewer/revoke-permission",
        data={"_csrf_token": tok,
              "permission_code": "mit leerzeichen"},
    )
    assert r.status_code == 400


# --- CSP + Leak ------------------------------------------------------ #

def test_roles_csp_header_present(app):
    c = create_role_client(app, "admin")
    r = c.get("/roles")
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp


_LEAK_MARKERS = (
    b"RoleRepository",
    b"RolePermissionRepository",
    b"core.access.repository",
    b"permission_id",
    b"AccessService",
    b"Traceback",
    b'  File "',
)


def _assert_no_leak(body: bytes) -> None:
    for m in _LEAK_MARKERS:
        assert m not in body, f"Leak: {m!r}"


def test_no_leak_list(app):
    c = create_role_client(app, "admin")
    r = c.get("/roles")
    _assert_no_leak(r.data)


def test_no_leak_detail(app):
    c = create_role_client(app, "admin")
    r = c.get("/roles/admin")
    _assert_no_leak(r.data)


def test_no_leak_detail_404(app):
    c = create_role_client(app, "admin")
    r = c.get("/roles/gibtsnicht")
    _assert_no_leak(r.data)


# --- A184/A193: self-critical Warnung -------------------------------- #

def test_role_detail_shows_self_warning(app):
    """
    Admin schaut auf die eigene Rolle 'admin' mit
    role.manage und principal.manage -> Warnung sichtbar.
    Exakter Wortlaut (A193): "Diese Rolle ist Ihre eigene".
    """
    c = create_role_client(app, "admin")
    r = c.get("/roles/admin")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Diese Rolle ist Ihre eigene" in body
    assert "Entzug von role.manage oder principal.manage" in body


def test_role_detail_no_self_warning_for_other_role(app):
    """Admin schaut auf viewer (fremde Rolle) -> keine Warnung."""
    c = create_role_client(app, "admin")
    r = c.get("/roles/viewer")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Diese Rolle ist Ihre eigene" not in body
