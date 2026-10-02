# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tests fuer apps/dashboard/routes_settings.py.

Kategorie 3 (Route, RBAC, read-only Konfigurationsanzeige).

Auflagen 207-218 aus Review-Runde 3.6.8i.
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


# --- RBAC ------------------------------------------------------------- #

def test_settings_without_session_redirects_to_login(app):
    c = app.test_client()
    r = c.get("/settings")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_settings_viewer_403(app):
    c = create_role_client(app, "viewer")
    r = c.get("/settings")
    assert r.status_code == 403


def test_settings_operator_403(app):
    c = create_role_client(app, "operator")
    r = c.get("/settings")
    assert r.status_code == 403


def test_settings_system_403(app):
    c = create_role_client(app, "system")
    r = c.get("/settings")
    assert r.status_code == 403


def test_settings_admin_200(app):
    c = create_role_client(app, "admin")
    r = c.get("/settings")
    assert r.status_code == 200


# --- Anzeige --------------------------------------------------------- #

def test_settings_shows_config_values(app):
    c = create_role_client(app, "admin")
    r = c.get("/settings")
    body = r.data.decode("utf-8", errors="replace")
    assert "Einstellungen" in body
    # DB-Pfad aus app.config
    assert str(app.config["DB_PATH"]) in body
    # Migrations-Pfad
    assert str(app.config["MIGRATIONS_DIR"]) in body
    # Audit-Pfad
    assert str(app.config["AUDIT_BASE_DIR"]) in body


def test_settings_shows_models(app):
    from core.config import (
        get_model_default,
        get_model_large,
        get_ollama_base_url,
    )
    c = create_role_client(app, "admin")
    r = c.get("/settings")
    body = r.data.decode("utf-8", errors="replace")
    assert get_model_default() in body
    assert get_model_large() in body
    assert get_ollama_base_url() in body


def test_settings_shows_security_self_report(app):
    c = create_role_client(app, "admin")
    r = c.get("/settings")
    body = r.data.decode("utf-8", errors="replace")
    # Cookie-Flags aus app.config
    assert "SESSION_COOKIE" not in body  # nur Werte, nicht Key-Namen
    assert "Selbstauskunft" in body


def test_settings_shows_section_not_in_this_round(app):
    c = create_role_client(app, "admin")
    r = c.get("/settings")
    body = r.data.decode("utf-8", errors="replace")
    assert "Nicht in dieser Runde" in body


# --- Kein Leak ------------------------------------------------------- #

def test_settings_does_not_leak_credentials(app):
    # Testname darf keine A214-Marker enthalten.
    # tmp_path wird aus dem Testnamen gebaut und
    # erscheint im /settings-Body (Audit-Verzeichnis).
    c = create_role_client(app, "admin")
    r = c.get("/settings")
    body = r.data
    assert b"SECRET_KEY" not in body
    assert b"secret_key" not in body
    assert b"os.environ" not in body
    assert b"/opt/security-ai/.venv" not in body
    assert b"password" not in body
    assert b"Passwort" not in body
    assert b"pbkdf2" not in body


def test_settings_body_has_no_credential_markers(app):
    # Neutraler Testname, damit tmp_path keine
    # A214-Marker enthaelt.
    c = create_role_client(app, "admin")
    r = c.get("/settings")
    body = r.data
    for m in (
        b"SECRET_KEY", b"secret_key", b"os.environ",
        b"/opt/security-ai/.venv", b"password",
        b"Passwort", b"pbkdf2",
    ):
        assert m not in body, f"Leak: {m!r}"


def test_settings_no_traceback_in_body(app):
    c = create_role_client(app, "admin")
    r = c.get("/settings")
    body = r.data
    assert b"Traceback" not in body
    assert b'  File "' not in body


# --- CSP ------------------------------------------------------------- #

def test_settings_csp_header_present(app):
    c = create_role_client(app, "admin")
    r = c.get("/settings")
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
