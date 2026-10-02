# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

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
from core.inventory.whitelist import WhitelistRepository
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


# ---------------------------------------------------------------------- #
# Punkt 48: IP auf der Detailseite
# ---------------------------------------------------------------------- #

def _seed_device_with_ip(app, identifier, ip=None):
    """Legt ein Geraet direkt in der Test-DB an."""
    conn = connect(app.config["DB_PATH"])
    try:
        repo = DeviceRepository(conn)
        repo.upsert_seen(
            identifier,
            entity_name="kamera",
            network_type="Hauptnetz",
            ip=ip,
        )
    finally:
        conn.close()


def test_inventory_detail_shows_ip(app):
    _seed_device_with_ip(app, "aa:bb:cc:dd:ee:99", ip="10.0.0.42")
    c = create_role_client(app, "viewer")
    r = c.get("/inventory/aa:bb:cc:dd:ee:99")
    assert r.status_code == 200
    assert b"10.0.0.42" in r.data


def test_inventory_detail_shows_dash_for_missing_ip(app):
    _seed_device_with_ip(app, "aa:bb:cc:dd:ee:98", ip=None)
    c = create_role_client(app, "viewer")
    r = c.get("/inventory/aa:bb:cc:dd:ee:98")
    assert r.status_code == 200
    # em-dash (UTF-8: e2 80 94) als Platzhalter.
    assert b"\xe2\x80\x94" in r.data


# --- Punkt 56a: Whitelist-Pflege (Route-Tests) ------------------------ #

def _client_with_csrf(app, role_name):
    """Client + aktuelles CSRF-Token (analog approvals)."""
    c = create_role_client(app, role_name)
    r = c.get("/inventory")
    # Token aus dem HTML: value="<token>"
    import re
    m = re.search(
        rb'data-csrf-token="([^"]+)"',
        r.get_data() or b"",
    )
    token = m.group(1).decode() if m else ""
    return c, token


def _is_whitelisted(app, identifier):
    conn = connect(app.config["DB_PATH"])
    try:
        return WhitelistRepository(conn).is_whitelisted(identifier)
    finally:
        conn.close()


def test_whitelist_add_route_requires_login(app):
    """Ohne Session: Redirect auf Login."""
    c = app.test_client()
    r = c.post("/inventory/aa:01/whitelist/add")
    assert r.status_code in (302, 303, 401)


def test_whitelist_add_route_rbac(app):
    """Viewer hat kein whitelist.manage -> 403."""
    _seed_device(app, "aa:01")
    c = create_role_client(app, "viewer")
    r = c.post("/inventory/aa:01/whitelist/add")
    assert r.status_code == 403


def test_whitelist_add_route_csrf(app):
    """Ohne CSRF-Token -> 400."""
    _seed_device(app, "aa:01")
    c = create_role_client(app, "admin")
    r = c.post(
        "/inventory/aa:01/whitelist/add",
        data={},
    )
    assert r.status_code == 400


def test_whitelist_add_route_ok(app):
    """Admin mit CSRF: Eintrag landet in der DB, Redirect 302."""
    _seed_device(app, "aa:01")
    c, tok = _client_with_csrf(app, "admin")
    r = c.post(
        "/inventory/aa:01/whitelist/add",
        data={"_csrf_token": tok},
    )
    assert r.status_code == 302
    assert _is_whitelisted(app, "aa:01")


def test_whitelist_remove_confirm_route(app):
    """GET-Bestaetigungsseite rendert."""
    _seed_device(app, "aa:01")
    c, tok = _client_with_csrf(app, "admin")
    c.post(
        "/inventory/aa:01/whitelist/add",
        data={"_csrf_token": tok},
    )
    r = c.get("/inventory/aa:01/whitelist/remove")
    assert r.status_code == 200
    assert b"Bestaetigung" in r.get_data()


def test_whitelist_remove_requires_confirm(app):
    """POST ohne CSRF -> 400, Eintrag bleibt."""
    _seed_device(app, "aa:01")
    c, tok = _client_with_csrf(app, "admin")
    c.post(
        "/inventory/aa:01/whitelist/add",
        data={"_csrf_token": tok},
    )
    r = c.post("/inventory/aa:01/whitelist/remove", data={})
    assert r.status_code == 400
    assert _is_whitelisted(app, "aa:01")


if __name__ == "__main__":
    import unittest
    unittest.main()


# --- Punkt 75: internal_name (Route-Tests) ---------------------------- #

def _get_internal_name(app, identifier):
    conn = connect(app.config["DB_PATH"])
    try:
        d = DeviceRepository(conn).get(identifier)
        return d.internal_name if d is not None else None
    finally:
        conn.close()


def test_internal_name_route_requires_login(app):
    c = app.test_client()
    r = c.post("/inventory/aa:01/internal_name", data={})
    assert r.status_code in (302, 303, 401)


def test_internal_name_route_rbac(app):
    _seed_device(app, "aa:01")
    c = create_role_client(app, "viewer")
    r = c.post(
        "/inventory/aa:01/internal_name",
        data={"internal_name": "X"},
    )
    assert r.status_code == 403


def test_internal_name_route_csrf(app):
    _seed_device(app, "aa:01")
    c = create_role_client(app, "admin")
    r = c.post("/inventory/aa:01/internal_name", data={})
    assert r.status_code == 400


def test_internal_name_route_ok(app):
    _seed_device(app, "aa:01")
    c, tok = _client_with_csrf(app, "admin")
    r = c.post(
        "/inventory/aa:01/internal_name",
        data={"_csrf_token": tok, "internal_name": "Server-Sandra"},
    )
    assert r.status_code == 302
    assert _get_internal_name(app, "aa:01") == "Server-Sandra"


def test_internal_name_visible_on_detail(app):
    _seed_device(app, "aa:01")
    c, tok = _client_with_csrf(app, "admin")
    c.post(
        "/inventory/aa:01/internal_name",
        data={"_csrf_token": tok, "internal_name": "Server-Sandra"},
    )
    r = c.get("/inventory/aa:01")
    assert r.status_code == 200
    assert b"Server-Sandra" in r.get_data()


if __name__ == "__main__":
    import unittest
    unittest.main()
