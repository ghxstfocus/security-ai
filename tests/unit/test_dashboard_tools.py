# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer apps/dashboard/routes_tools.py (Punkt 58, Auflage 1991).

13 Pflicht-Faelle:
  Seite, RBAC, CSRF, Body, Tool-Lookup, Key-Whitelist,
  Audit original_args, Rate-Limit, no-store.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from apps.dashboard import csrf
from harness.permissions.levels import Level
from harness.tool_registry.registry import ToolRegistry
from harness.tool_registry.tool import Tool
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


def _post_run(client, tok, body, content_type="application/json"):
    headers = {}
    if tok is not None:
        headers["X-CSRF-Token"] = tok
    if content_type is not None:
        headers["Content-Type"] = content_type
    return client.post(
        "/api/tools/run", data=body, headers=headers,
    )


def _stub_ping_registry(app, func):
    """Ersetzt app.extensions["workbench_registry"] durch eine
    Registry mit nur einem ping-Tool. Verhindert echten
    subprocess-Aufruf."""
    reg = ToolRegistry()
    reg.register(Tool(
        name="ping",
        level=Level.READ,
        func=func,
        description="test-ping",
        sandbox_profile="net_diag_local",
        allowed_args=frozenset({"target"}),
    ))
    app.extensions["workbench_registry"] = reg


# --- Seite ---------------------------------------------------------------- #

def test_tools_page_redirects_without_login(app):
    c = app.test_client()
    r = c.get("/tools")
    assert r.status_code in (302, 303, 401)


def test_tools_page_ok_with_admin(app):
    c, _ = _client_with_csrf(app, "admin")
    r = c.get("/tools")
    assert r.status_code == 200


def test_tools_page_ok_with_viewer(app):
    c, _ = _client_with_csrf(app, "viewer")
    r = c.get("/tools")
    assert r.status_code == 200


# --- CSRF ----------------------------------------------------------------- #

def test_api_tools_run_without_csrf(app):
    c = create_role_client(app, "admin")
    body = json.dumps({"tool": "ping", "args": {"target": "127.0.0.1"}})
    r = c.post(
        "/api/tools/run", data=body,
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 400


# --- Body / Tool-Lookup --------------------------------------------------- #

def test_api_tools_run_unknown_tool(app):
    c, tok = _client_with_csrf(app, "admin")
    body = json.dumps({"tool": "does_not_exist", "args": {}})
    r = _post_run(c, tok, body)
    assert r.status_code == 400


def test_api_tools_run_invalid_body(app):
    c, tok = _client_with_csrf(app, "admin")
    body = json.dumps({"tool": 42})
    r = _post_run(c, tok, body)
    assert r.status_code == 400


# --- RBAC ----------------------------------------------------------------- #

def test_api_tools_run_rbac_denied(app):
    _stub_ping_registry(app, lambda target: {"ok": True})
    c, tok = _client_with_csrf(app, "viewer")
    body = json.dumps({"tool": "ping", "args": {"target": "127.0.0.1"}})
    r = _post_run(c, tok, body)
    assert r.status_code == 403


def test_api_tools_run_without_login(app):
    c = app.test_client()
    body = json.dumps({"tool": "ping", "args": {"target": "127.0.0.1"}})
    r = c.post(
        "/api/tools/run", data=body,
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code in (302, 303, 401)


# --- Erfolg + Key-Whitelist + Audit --------------------------------------- #

def test_api_tools_run_success(app):
    calls = []
    def fake_ping(target: str) -> dict:
        calls.append({"target": target})
        return {"ok": True, "target": target}
    _stub_ping_registry(app, fake_ping)
    c, tok = _client_with_csrf(app, "admin")
    body = json.dumps({"tool": "ping", "args": {"target": "127.0.0.1"}})
    r = _post_run(c, tok, body)
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data["tool"] == "ping"
    assert data["error"] is None
    assert len(calls) == 1
    assert calls[0] == {"target": "127.0.0.1"}


def test_api_tools_run_unknown_key_filtered(app):
    calls = []
    def fake_ping(**kwargs: Any) -> dict:
        calls.append(kwargs)
        return {"ok": True}
    _stub_ping_registry(app, fake_ping)
    c, tok = _client_with_csrf(app, "admin")
    body = json.dumps({
        "tool": "ping",
        "args": {"target": "127.0.0.1", "evil": "x"},
    })
    r = _post_run(c, tok, body)
    assert r.status_code == 200
    assert len(calls) == 1
    assert "evil" not in calls[0]
    assert calls[0] == {"target": "127.0.0.1"}


def test_api_tools_run_unknown_key_audited(app):
    def fake_ping(target: str) -> dict:
        return {"ok": True}
    _stub_ping_registry(app, fake_ping)
    c, tok = _client_with_csrf(app, "admin")
    body = json.dumps({
        "tool": "ping",
        "args": {"target": "127.0.0.1", "evil": "x"},
    })
    r = _post_run(c, tok, body)
    assert r.status_code == 200
    audit_dir = Path(app.config["AUDIT_BASE_DIR"])
    files = sorted(audit_dir.glob("*.jsonl"))
    assert files, "kein audit-log geschrieben"
    lines = files[-1].read_text(encoding="utf-8").splitlines()
    last = json.loads(lines[-1])
    assert last["tool"] == "ping"
    assert last["details"]["kind"] == "tool_call"
    assert last["details"]["source"] == "ui"
    assert "args_hash" in last


# --- Rate-Limit ----------------------------------------------------------- #

def test_api_tools_run_rate_limit_returns_429(app):
    _stub_ping_registry(app, lambda target: {"ok": True})
    c, tok = _client_with_csrf(app, "admin")
    body = json.dumps({"tool": "ping", "args": {"target": "127.0.0.1"}})
    for _ in range(10):
        r = _post_run(c, tok, body)
        assert r.status_code == 200, r.get_data(as_text=True)
    r11 = _post_run(c, tok, body)
    assert r11.status_code == 429
    assert r11.headers.get("Retry-After") is not None


# --- no-store ------------------------------------------------------------- #

def test_api_tools_run_response_has_no_store(app):
    _stub_ping_registry(app, lambda target: {"ok": True})
    c, tok = _client_with_csrf(app, "admin")
    body = json.dumps({"tool": "ping", "args": {"target": "127.0.0.1"}})
    r = _post_run(c, tok, body)
    assert r.headers.get("Cache-Control") == "no-store"
    body2 = json.dumps({"tool": "does_not_exist", "args": {}})
    r2 = _post_run(c, tok, body2)
    assert r2.status_code == 400
    assert r2.headers.get("Cache-Control") == "no-store"
