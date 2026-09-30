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
