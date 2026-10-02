# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tests fuer apps/dashboard/auth.py.

Kategorie 3 (RBAC, Session, CSRF, Rate-Limit,
Audit).

Auflage 174: CSRF via session_transaction.
Auflage 176: read_audit_lines lokal.
Auflage 181: test_login_missing_fields_400 mit
             3 Sub-Faellen.
Auflage 183: Cookie 4 Attribute.
Auflage 184: Logout-CSRF-Fehler ohne Audit.
Auflage 185: Hard-Limit via app.config.
Auflage 186: whoami ohne Session -> 302.
Auflage 187: whoami JSON.
Auflage 205: Helper mit is_active.
Auflage 206: hash_password Default 600k.
Auflage 208: Test 302 mit/ohne next.
Auflage 210: SessionRepository importiert oben.
Auflage 212: test_logout_without_session_redirects.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from apps.dashboard.auth import _safe_next
from apps.dashboard.decorators import SESSION_COOKIE_NAME
from core.access.models import (
    PrincipalKind,
    hash_password,
)
from core.access.repository import (
    PrincipalRepository,
    RoleRepository,
)
from core.access.session_repo import SessionRepository
from core.inventory.repository import (
    connect,
)
from tests.unit._helpers import (
    build_dashboard_app,
    set_session_cookie,
)


@pytest.fixture()
def app(tmp_path: Path):
    a = build_dashboard_app(tmp_path)
    a.config["LOGIN_MAX_FAILURES"] = 2
    a.config["LOGIN_HARD_LIMIT"] = 10
    return a


@pytest.fixture()
def anon_client(app):
    return app.test_client()


def _create_principal_with_password(
    app, name, role_name, password, *,
    is_active=True,
):
    conn = connect(app.config["DB_PATH"])
    roles = RoleRepository(conn)
    principals = PrincipalRepository(conn)
    role = roles.get_by_name(role_name)
    principals.create(
        name=name, role_id=role.row_id,
        kind=PrincipalKind.HUMAN,
        password_hash=hash_password(password),
        is_active=is_active,
    )
    conn.close()


def _get_csrf(client):
    client.get("/login")
    with client.session_transaction() as sess:
        return sess["_csrf_token"]


def read_audit_lines(audit_dir: Path) -> list[dict]:
    out: list[dict] = []
    for p in sorted(audit_dir.glob("*.jsonl")):
        for raw in p.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if raw:
                out.append(json.loads(raw))
    return out


# ---------------------------------------------------------------------- #
# CSRF-Tests (2)
# ---------------------------------------------------------------------- #

def test_login_missing_csrf_400(anon_client):
    r = anon_client.post(
        "/login",
        data={"principal": "x", "password": "y"},
    )
    assert r.status_code == 400


def test_login_wrong_csrf_400(anon_client):
    anon_client.get("/login")
    r = anon_client.post(
        "/login",
        data={
            "_csrf_token": "falsch",
            "principal": "x",
            "password": "y",
        },
    )
    assert r.status_code == 400


# ---------------------------------------------------------------------- #
# Login-Basis-Tests (4)
# ---------------------------------------------------------------------- #

def test_login_missing_fields_400(anon_client):
    token = _get_csrf(anon_client)
    for data in (
        {"_csrf_token": token, "password": "x"},
        {"_csrf_token": token, "principal": "x"},
        {"_csrf_token": token, "principal": "",
         "password": ""},
    ):
        r = anon_client.post("/login", data=data)
        assert r.status_code == 400


def test_login_unknown_principal_401(anon_client):
    token = _get_csrf(anon_client)
    r = anon_client.post(
        "/login",
        data={
            "_csrf_token": token,
            "principal": "nichtda",
            "password": "x",
        },
    )
    assert r.status_code == 401


def test_login_wrong_password_401(app, anon_client):
    _create_principal_with_password(
        app, "u1", "viewer", "korrekt",
    )
    token = _get_csrf(anon_client)
    r = anon_client.post(
        "/login",
        data={
            "_csrf_token": token,
            "principal": "u1",
            "password": "falsch",
        },
    )
    assert r.status_code == 401


def test_login_inactive_401(app, anon_client):
    # Auflage 204 + 216
    _create_principal_with_password(
        app, "u2", "viewer", "korrekt",
        is_active=False,
    )
    token = _get_csrf(anon_client)
    r = anon_client.post(
        "/login",
        data={
            "_csrf_token": token,
            "principal": "u2",
            "password": "korrekt",
        },
    )
    assert r.status_code == 401
    lines = read_audit_lines(
        Path(app.config["AUDIT_BASE_DIR"]),
    )
    kinds = [
        e.get("details", {}).get("kind") for e in lines
    ]
    assert "login_locked" in kinds
    assert "login_failed" not in kinds



# ---------------------------------------------------------------------- #
# Login-Erfolg-Tests (4)
# ---------------------------------------------------------------------- #

def test_login_success_302(app, anon_client):
    _create_principal_with_password(
        app, "u3", "viewer", "korrekt",
    )
    token = _get_csrf(anon_client)
    r = anon_client.post(
        "/login",
        data={
            "_csrf_token": token,
            "principal": "u3",
            "password": "korrekt",
        },
    )
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/")


def test_login_success_302_with_next(app, anon_client):
    _create_principal_with_password(
        app, "u4", "viewer", "korrekt",
    )
    token = _get_csrf(anon_client)
    r = anon_client.post(
        "/login",
        data={
            "_csrf_token": token,
            "principal": "u4",
            "password": "korrekt",
            "next": "/whoami",
        },
    )
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/whoami")


def test_login_session_cookie_set(app, anon_client):
    _create_principal_with_password(
        app, "u5", "viewer", "korrekt",
    )
    token = _get_csrf(anon_client)
    r = anon_client.post(
        "/login",
        data={
            "_csrf_token": token,
            "principal": "u5",
            "password": "korrekt",
        },
    )
    set_cookie = r.headers.get("Set-Cookie", "")
    assert SESSION_COOKIE_NAME in set_cookie
    assert "HttpOnly" in set_cookie
    assert "Secure" in set_cookie
    assert "SameSite=Strict" in set_cookie


def test_login_rotates_session(app, anon_client):
    # Auflage 214: neue Session-ID aus Set-Cookie
    _create_principal_with_password(
        app, "u6", "viewer", "korrekt",
    )
    set_session_cookie(anon_client, "sid-1")
    token = _get_csrf(anon_client)
    r = anon_client.post(
        "/login",
        data={
            "_csrf_token": token,
            "principal": "u6",
            "password": "korrekt",
        },
    )
    assert r.status_code == 302
    set_cookie = r.headers.get("Set-Cookie", "")
    m = re.search(
        rf"{SESSION_COOKIE_NAME}=([^;]+)", set_cookie,
    )
    assert m is not None
    new_sid = m.group(1)
    assert new_sid != "sid-1"
    conn = connect(app.config["DB_PATH"])
    sr = SessionRepository(conn)
    old = sr.get("sid-1")
    new_s = sr.get(new_sid)
    conn.close()
    assert old is not None
    assert old.revoked_at is not None
    assert new_s is not None
    assert new_s.principal_name == "u6"


# ---------------------------------------------------------------------- #
# Audit-Tests (2)
# ---------------------------------------------------------------------- #

def test_login_audit_success(app, anon_client):
    _create_principal_with_password(
        app, "u7", "viewer", "korrekt",
    )
    token = _get_csrf(anon_client)
    anon_client.post(
        "/login",
        data={
            "_csrf_token": token,
            "principal": "u7",
            "password": "korrekt",
        },
    )
    lines = read_audit_lines(
        Path(app.config["AUDIT_BASE_DIR"]),
    )
    kinds = [
        e.get("details", {}).get("kind") for e in lines
    ]
    assert "login_success" in kinds


def test_login_audit_failed(app, anon_client):
    _create_principal_with_password(
        app, "u8", "viewer", "korrekt",
    )
    token = _get_csrf(anon_client)
    anon_client.post(
        "/login",
        data={
            "_csrf_token": token,
            "principal": "u8",
            "password": "falsch",
        },
    )
    lines = read_audit_lines(
        Path(app.config["AUDIT_BASE_DIR"]),
    )
    kinds = [
        e.get("details", {}).get("kind") for e in lines
    ]
    assert "login_failed" in kinds


# ---------------------------------------------------------------------- #
# Rate-Limit-Tests (2)
# ---------------------------------------------------------------------- #

def test_rate_limit_locked_401(app, anon_client):
    _create_principal_with_password(
        app, "u9", "viewer", "korrekt",
    )
    token = _get_csrf(anon_client)
    for _ in range(2):
        anon_client.post(
            "/login",
            data={
                "_csrf_token": token,
                "principal": "u9",
                "password": "falsch",
            },
        )
    r = anon_client.post(
        "/login",
        data={
            "_csrf_token": token,
            "principal": "u9",
            "password": "falsch",
        },
    )
    assert r.status_code == 401


def test_rate_limit_hard_429(app, anon_client):
    # Auflage 185
    app.config["LOGIN_HARD_LIMIT"] = 1
    app.config["LOGIN_MAX_FAILURES"] = 1
    _create_principal_with_password(
        app, "u10", "viewer", "korrekt",
    )
    token = _get_csrf(anon_client)
    anon_client.post(
        "/login",
        data={
            "_csrf_token": token,
            "principal": "u10",
            "password": "falsch",
        },
    )
    r = anon_client.post(
        "/login",
        data={
            "_csrf_token": token,
            "principal": "u10",
            "password": "falsch",
        },
    )
    assert r.status_code == 429


# ---------------------------------------------------------------------- #
# Logout-Tests (3)
# ---------------------------------------------------------------------- #

def test_logout_csrf_400(app, anon_client):
    # Auflage 184 + 213
    set_session_cookie(anon_client, "sid-1")
    r = anon_client.post(
        "/logout", data={"_csrf_token": "falsch"},
    )
    assert r.status_code == 400
    conn = connect(app.config["DB_PATH"])
    sr = SessionRepository(conn)
    old = sr.get("sid-1")
    conn.close()
    assert old is not None
    assert old.revoked_at is None
    lines = read_audit_lines(
        Path(app.config["AUDIT_BASE_DIR"]),
    )
    kinds = [
        e.get("details", {}).get("kind") for e in lines
    ]
    assert "logout" not in kinds


def test_logout_success_302(app, anon_client):
    # Auflage 218
    set_session_cookie(anon_client, "sid-1")
    token = _get_csrf(anon_client)
    r = anon_client.post(
        "/logout",
        data={"_csrf_token": token},
    )
    assert r.status_code == 302
    conn = connect(app.config["DB_PATH"])
    sr = SessionRepository(conn)
    old = sr.get("sid-1")
    conn.close()
    assert old is not None
    assert old.revoked_at is not None
    lines = read_audit_lines(
        Path(app.config["AUDIT_BASE_DIR"]),
    )
    kinds = [
        e.get("details", {}).get("kind") for e in lines
    ]
    assert "logout" in kinds
    set_cookie = r.headers.get("Set-Cookie", "")
    assert SESSION_COOKIE_NAME in set_cookie


def test_logout_without_session_redirects(anon_client):
    # Auflage 211 + 212
    token = _get_csrf(anon_client)
    r = anon_client.post(
        "/logout",
        data={"_csrf_token": token},
    )
    assert r.status_code == 302


# ---------------------------------------------------------------------- #
# whoami-Tests (2)
# ---------------------------------------------------------------------- #

def test_whoami_requires_session(anon_client):
    # Auflage 186
    r = anon_client.get("/whoami")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_whoami_ok(anon_client):
    # Auflage 187
    set_session_cookie(anon_client, "sid-1")
    r = anon_client.get("/whoami")
    assert r.status_code == 200
    assert "application/json" in r.headers["Content-Type"]
    body = r.get_json()
    assert "principal" in body
    assert "role" in body
    assert "permissions" in body


# ---------------------------------------------------------------------- #
# _safe_next (Auflage 166 + 219)
# ---------------------------------------------------------------------- #

def test_safe_next_blocks_url_encoded_bypass():
    assert _safe_next("%2F%2Fevil.com") == "/"
    assert _safe_next("/%5Cevil.com") == "/"
    assert _safe_next("/\\evil.com") == "/"
    assert _safe_next("") == "/"
    assert _safe_next(None) == "/"
    assert _safe_next("/ok") == "/ok"
    assert _safe_next("/ok?x=1") == "/ok?x=1"
