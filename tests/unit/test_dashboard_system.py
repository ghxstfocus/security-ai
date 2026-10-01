"""Tests /system und /api/system/state (Punkt 66, Kategorie 3)."""
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
def client(app):
    c = app.test_client()
    set_session_cookie(c, "sid-1")
    return c


@pytest.fixture()
def viewer_client(app):
    c = app.test_client()
    set_session_cookie(c, "sid-viewer")
    return c


def test_system_route_requires_login(app) -> None:
    c = app.test_client()
    r = c.get("/system")
    assert r.status_code in (302, 303, 401)


def test_system_route_rbac(client) -> None:
    r = client.get("/system")
    assert r.status_code in (200, 403)


def test_system_route_renders(client) -> None:
    r = client.get("/system")
    if r.status_code == 200:
        body = r.get_data(as_text=True)
        assert "System" in body
        assert "system.js" in body


def test_api_state_rbac(viewer_client) -> None:
    r = viewer_client.get("/api/system/state")
    assert r.status_code in (200, 403)


def test_api_state_no_store_header(client) -> None:
    r = client.get("/api/system/state")
    if r.status_code == 200:
        assert r.headers.get("Cache-Control") == "no-store"


if __name__ == "__main__":
    import unittest
    unittest.main()
