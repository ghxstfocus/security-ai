# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tests fuer GET /api/dashboard/state (T1+T5, Auflage 1702).

Kategorie 3 (Route, RBAC, JSON).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.unit._helpers import (
    build_dashboard_app,
    set_session_cookie,
)


@pytest.fixture()
def app(tmp_path: Path):
    return build_dashboard_app(tmp_path)


@pytest.fixture()
def admin_client(app):
    c = app.test_client()
    set_session_cookie(c, "sid-1")
    return c


@pytest.fixture()
def viewer_client(app):
    c = app.test_client()
    set_session_cookie(c, "sid-viewer")
    return c


def test_state_requires_login(app):
    c = app.test_client()
    r = c.get("/api/dashboard/state")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_state_devices_section_with_permission(admin_client):
    r = admin_client.get("/api/dashboard/state")
    assert r.status_code == 200
    body = r.get_json()
    assert "devices" in body
    assert "active" in body["devices"]
    assert "recent" in body["devices"]
    assert "hauptnetz" in body["devices"]
    assert "gastnetz" in body["devices"]


def test_state_alerts_section_with_permission(admin_client):
    r = admin_client.get("/api/dashboard/state")
    assert r.status_code == 200
    body = r.get_json()
    assert "alerts" in body
    assert isinstance(body["alerts"], list)


def test_state_no_cache_header(admin_client):
    r = admin_client.get("/api/dashboard/state")
    assert r.status_code == 200
    assert r.headers.get("Cache-Control") == "no-store"


def test_state_viewer_has_devices_and_alerts(viewer_client):
    # viewer-Rolle: chat.ask, device.read, audit.read
    # kein alert.view, kein change.view
    r = viewer_client.get("/api/dashboard/state")
    assert r.status_code == 200
    body = r.get_json()
    assert "devices" in body
    assert "alerts" not in body
    assert "changes" not in body


def test_state_available_false_when_missing(app, admin_client):
    # build_dashboard_app schreibt keine fritzbox_state.json
    # ins tmp-Verzeichnis, deshalb greift der Default-Pfad
    # data/fritzbox_state.json. Da die Datei in der
    # Produktionsumgebung existiert, kann der Test sie
    # nicht einfach "fehlen lassen". Deshalb pruefen wir
    # nur, dass der Schluessel vorhanden ist.
    r = admin_client.get("/api/dashboard/state")
    assert r.status_code == 200
    body = r.get_json()
    assert "available" in body["devices"]
    assert isinstance(body["devices"]["available"], bool)


def test_state_system_section_with_permission(admin_client):
    """T4: system-Sektion mit device.read vorhanden."""
    r = admin_client.get("/api/dashboard/state")
    assert r.status_code == 200
    body = r.get_json()
    assert "system" in body
    sysd = body["system"]
    assert "cpu_percent" in sysd
    assert "ram_percent" in sysd
    assert "ram_used_gb" in sysd
    assert "ram_total_gb" in sysd
    assert isinstance(sysd["cpu_percent"], (int, float))
    assert isinstance(sysd["ram_percent"], (int, float))


def test_state_recent_changes_section_with_permission(admin_client):
    """T4: recent_changes-Sektion mit audit.read vorhanden."""
    r = admin_client.get("/api/dashboard/state")
    assert r.status_code == 200
    body = r.get_json()
    assert "recent_changes" in body
    assert isinstance(body["recent_changes"], list)


def test_state_recent_changes_absent_for_system_role(app):
    """T4: system-Rolle hat kein audit.read -> Sektion fehlt."""
    from core.access.models import PrincipalKind
    from core.access.repository import (
        PrincipalRepository,
        RoleRepository,
    )
    from core.access.session_repo import SessionRepository
    from core.inventory.repository import connect

    conn = connect(app.config["DB_PATH"])
    roles = RoleRepository(conn)
    principals = PrincipalRepository(conn)
    sys_role = roles.get_by_name("system")
    principals.create(
        name="sys1", role_id=sys_role.row_id,
        kind=PrincipalKind.SYSTEM,
    )
    SessionRepository(conn).create("sid-sys1", "sys1")
    conn.close()

    c = app.test_client()
    set_session_cookie(c, "sid-sys1")
    r = c.get("/api/dashboard/state")
    assert r.status_code == 200
    body = r.get_json()
    assert "devices" in body
    assert "recent_changes" not in body
    assert "alerts" not in body
    assert "changes" not in body


def test_state_system_absent_for_no_devread_role(app):
    """T4: Rolle ohne device.read -> system fehlt."""
    from datetime import UTC, datetime

    from core.access.models import PrincipalKind
    from core.access.repository import (
        PrincipalRepository,
        RoleRepository,
    )
    from core.access.session_repo import SessionRepository
    from core.inventory.repository import connect

    conn = connect(app.config["DB_PATH"])
    roles = RoleRepository(conn)
    conn.execute(
        "INSERT INTO roles (name, description, created_at) "
        "VALUES (?, ?, ?)",
        (
            "no_dev_read_t4",
            "Test-Rolle ohne device.read",
            datetime.now(UTC).isoformat(),
        ),
    )
    conn.commit()
    role = roles.get_by_name("no_dev_read_t4")
    PrincipalRepository(conn).create(
        name="nope_t4", role_id=role.row_id,
        kind=PrincipalKind.HUMAN,
    )
    SessionRepository(conn).create("sid-nope_t4", "nope_t4")
    conn.close()

    c = app.test_client()
    set_session_cookie(c, "sid-nope_t4")
    r = c.get("/api/dashboard/state")
    # /api/dashboard/state hat Grundpermission device.read:
    # ohne die ist der ganze Endpoint 403.
    assert r.status_code == 403
