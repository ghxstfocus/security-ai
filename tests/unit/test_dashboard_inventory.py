"""
Tests fuer apps/dashboard/routes_inventory.py + InventoryService.

Kategorie 3 (Routes, RBAC, Templates, Input-Validierung).

Auflagen 1-14 aus Review-Runde 3.6.8a.
"""
from __future__ import annotations

from datetime import UTC
from pathlib import Path

import pytest

from core.access.checker import AccessChecker
from core.access.models import PrincipalKind
from core.access.repository import (
    PrincipalRepository,
    RoleRepository,
)
from core.access.session_repo import SessionRepository
from core.inventory.repository import (
    DeviceRepository,
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


def _make_no_devread_client(app):
    """
    Eigene Rolle 'no_dev_read' + Principal + Session.
    Migration 0005 gibt allen Rollen device.read, daher
    hier eine Rolle ohne diese Permission anlegen.

    principals.role_id ist eine einzelne Spalte (FK) —
    eine Rolle pro Principal, Auflage 11 automatisch ok.
    """
    conn = connect(app.config["DB_PATH"])
    try:
        from datetime import datetime
        roles = RoleRepository(conn)
        conn.execute(
            "INSERT INTO roles (name, description, created_at) "
            "VALUES (?, ?, ?)",
            (
                "no_dev_read",
                "Test-Rolle ohne device.read",
                datetime.now(UTC).isoformat(),
            ),
        )
        conn.commit()
        role = roles.get_by_name("no_dev_read")
        PrincipalRepository(conn).create(
            name="nodev1", role_id=role.row_id,
            kind=PrincipalKind.HUMAN,
        )
        SessionRepository(conn).create("sid-nodev", "nodev1")
        perms = AccessChecker.from_conn(conn).permissions_of(
            "nodev1"
        )
        assert "device.read" not in perms, (
            "Test-Rolle no_dev_read hat unerwartet device.read"
        )
    finally:
        conn.close()
    c = app.test_client()
    set_session_cookie(c, "sid-nodev")
    return c


def _seed_device(app, identifier, *, name="host-a",
                 network_type="Hauptnetz"):
    conn = connect(app.config["DB_PATH"])
    try:
        DeviceRepository(conn).upsert_seen(
            identifier,
            entity_name=name,
            network_type=network_type,
        )
    finally:
        conn.close()


# --- RBAC ------------------------------------------------------------- #

def test_inventory_without_session_redirects_to_login(app):
    c = app.test_client()
    r = c.get("/inventory")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_inventory_without_device_read_403(app):
    c = _make_no_devread_client(app)
    r = c.get("/inventory")
    assert r.status_code == 403


def test_inventory_detail_without_device_read_403(app):
    c = _make_no_devread_client(app)
    r = c.get("/inventory/1.2.3.4")
    assert r.status_code == 403


# --- Happy Path ------------------------------------------------------- #

def test_inventory_empty_shows_placeholder(app):
    c = create_role_client(app, "viewer")
    r = c.get("/inventory")
    assert r.status_code == 200
    assert b"Keine Geraete erfasst" in r.data


def test_inventory_lists_device_with_whitelist_flag(app):
    _seed_device(app, "1.2.3.4")
    c = create_role_client(app, "viewer")
    r = c.get("/inventory")
    assert r.status_code == 200
    assert b"1.2.3.4" in r.data
    assert b"nein" in r.data


def test_inventory_detail_shows_history(app):
    _seed_device(app, "1.2.3.4")
    c = create_role_client(app, "viewer")
    r = c.get("/inventory/1.2.3.4")
    assert r.status_code == 200
    assert b"1.2.3.4" in r.data
    assert b"device_seen" in r.data


# --- 404-Faelle (Auflage 8) ------------------------------------------- #

@pytest.mark.parametrize("identifier", [
    "unbekannt",
    "a..b",
    "..",
    ".",
    "-x",
    "x-",
    "_x",
    pytest.param("a" * 256, id="len256"),
    "mit space",
])
def test_inventory_detail_invalid_or_unknown_404(app, identifier):
    c = create_role_client(app, "viewer")
    r = c.get("/inventory/" + identifier)
    assert r.status_code == 404


# --- fail closed fuer unmatched Routes (Auflage 17) ---------------- #

def test_unmatched_route_403_fail_closed(app):
    """
    Pfade, die auf keine View matchen, erhalten 403 aus
    before_request (View ohne _required_permission).
    Fail closed, kein Route-Existenz-Oracle.
    Kein Service-Content im Body.
    """
    c = create_role_client(app, "viewer")
    for path in ("/inventory/", "/inventory/sla/sh"):
        r = c.get(path)
        assert r.status_code == 403
        assert b"identifier" not in r.data.lower()
        assert b"device_repo" not in r.data.lower()
        assert b"inventoryservice" not in r.data.lower()


# --- URL-kodiert (Auflage 12) ---------------------------------------- #

@pytest.mark.parametrize("identifier", ["x%00", "x%2e%2e"])
def test_inventory_detail_urlencoded_400_or_404(app, identifier):
    # Auflage 12: Framework-400 (Werkzeug) oder unser 404,
    # beides ok. Kein url_map-Override.
    c = create_role_client(app, "viewer")
    r = c.get("/inventory/" + identifier)
    assert r.status_code in (400, 404)


# --- XSS + CSP (Auflage 9) -------------------------------------------- #

def test_inventory_escapes_xss_in_entity_name(app):
    payload = "<img src=x onerror=alert(1)>"
    _seed_device(app, "1.2.3.4", name=payload)
    c = create_role_client(app, "viewer")
    r = c.get("/inventory")
    assert r.status_code == 200
    assert b"<img src=x" not in r.data
    assert b"&lt;img src=x onerror=alert(1)&gt;" in r.data


def test_inventory_csp_header_present(app):
    c = create_role_client(app, "viewer")
    r = c.get("/inventory")
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
