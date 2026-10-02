# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Dashboard-Suche: Route, RBAC, XSS, Links (3.6.16, A559).

Nutzt build_dashboard_app + create_role_client.
viewer hat KEIN search.run (Migration 0008),
admin1 schon.
"""
from __future__ import annotations

from tests.unit._helpers import build_dashboard_app, create_role_client


def _seed_change(app, change_id="CHG-2026-09999",
                 title="Test-Kamera"):
    from core.inventory.repository import connect
    conn = connect(app.config["DB_PATH"])
    conn.execute(
        "INSERT INTO change_requests (change_id, timestamp, title, "
        "description, requested_by, status, type, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (change_id, "2026-09-26T10:00:00+00:00", title,
         "d", "admin-web", "draft", "config_change",
         "2026-09-26T10:00:00+00:00"),
    )
    conn.commit()
    conn.close()


def test_search_requires_permission(tmp_path):
    app = build_dashboard_app(tmp_path)
    c = create_role_client(app, "viewer")
    r = c.get("/search?q=kamera")
    assert r.status_code == 403


def test_search_admin_200(tmp_path):
    app = build_dashboard_app(tmp_path)
    c = create_role_client(app, "admin")
    r = c.get("/search?q=kamera")
    assert r.status_code == 200


def test_search_no_post(tmp_path):
    # POST /search matcht die Route nicht (nur GET).
    # before_request findet keine View mit
    # _required_permission -> Sicherheitsnetz 403
    # (nicht 405). Fail closed, Auflage 551.
    app = build_dashboard_app(tmp_path)
    c = create_role_client(app, "admin")
    r = c.post("/search", data={"q": "kamera"})
    assert r.status_code in (403, 405)
    assert r.status_code != 200


def test_search_too_short_400(tmp_path):
    app = build_dashboard_app(tmp_path)
    c = create_role_client(app, "admin")
    r = c.get("/search?q=a")
    assert r.status_code == 400
    # A551: kein Echo des q, kein "q=a" im Body.
    assert b"q=a" not in r.data
    assert b"search" not in r.data.lower()


def test_search_invalid_chars_400(tmp_path):
    app = build_dashboard_app(tmp_path)
    c = create_role_client(app, "admin")
    r = c.get("/search?q=ab%3Cscript%3E")
    assert r.status_code == 400


def test_search_hit_links_to_detail(tmp_path):
    app = build_dashboard_app(tmp_path)
    _seed_change(app)
    c = create_role_client(app, "admin")
    r = c.get("/search?q=Test-Kamera")
    assert r.status_code == 200
    assert b"/changes/CHG-2026-09999" in r.data


def test_search_q_escaped(tmp_path):
    app = build_dashboard_app(tmp_path)
    c = create_role_client(app, "admin")
    r = c.get("/search?q=ab%3Cscript%3E")
    assert b"<script>" not in r.data


def test_search_viewer_no_changes_link(tmp_path):
    # viewer hat kein search.run -> 403, nicht "changes sichtbar"
    app = build_dashboard_app(tmp_path)
    _seed_change(app)
    c = create_role_client(app, "viewer")
    r = c.get("/search?q=Test-Kamera")
    assert r.status_code == 403
    assert b"CHG-2026-09999" not in r.data


def test_search_empty_q(tmp_path):
    app = build_dashboard_app(tmp_path)
    c = create_role_client(app, "admin")
    r = c.get("/search")
    assert r.status_code == 400
