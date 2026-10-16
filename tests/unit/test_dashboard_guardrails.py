# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer apps/dashboard/routes_guardrails.py (Phase 5).

Vier Faelle:
  (1) admin -> 200.
  (2) viewer -> 200 (viewer hat guardrail.view aus 0018).
  (3) system -> 403 (system hat KEIN guardrail.view).
  (4) Template CSP-konform (kein style=, onclick=, <script).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.unit._helpers import (
    build_dashboard_app,
    create_role_client,
)


@pytest.fixture()
def app(tmp_path: Path):
    return build_dashboard_app(tmp_path)


def test_guardrails_admin_ok(app):
    c = create_role_client(app, "admin")
    r = c.get("/guardrails")
    assert r.status_code == 200


def test_guardrails_viewer_ok(app):
    c = create_role_client(app, "viewer")
    r = c.get("/guardrails")
    assert r.status_code == 200


def test_guardrails_403_ohne_permission(app):
    c = create_role_client(app, "system")
    r = c.get("/guardrails")
    assert r.status_code == 403


def test_guardrails_template_csp_konform():
    quelle = Path(
        "apps/dashboard/templates/guardrails.html"
    ).read_text(encoding="utf-8")
    assert "style=" not in quelle
    assert "onclick=" not in quelle
    assert "<script" not in quelle