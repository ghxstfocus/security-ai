"""
Tests fuer apps/dashboard/routes_alerts.py.

Kategorie 3 (Route, RBAC, Template).

Auflagen 26-29 aus Review-Runde 3.6.8b:
- A26: Badge zeigt Kategorie-Text, nicht nur Farbe.
- A27: viewer -> 403 (Absicherung gegen spaetere Migration).
- A28: unbekannte Kategorie sichtbar + badge-cyan.
- A29: kein JS, kein |safe, kein tojson.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.inventory.repository import connect
from harness.audit.writer import AuditWriter
from tests.unit._helpers import (
    build_dashboard_app,
    create_role_client,
)


@pytest.fixture()
def app(tmp_path: Path):
    return build_dashboard_app(tmp_path)


def _write_assessment(app, *, category="CONFIRMED",
                      score=0.85, rule_id="unknown_device",
                      event_id="EVT-2026-09-22-deadbeef"):
    """
    Schreibt einen risk_assessment-Eintrag in den tmp-Audit.
    AuditWriter aus app.extensions["audit_writer"] nutzen,
    damit der Pfad stimmt.
    """
    writer: AuditWriter = app.extensions["audit_writer"]
    writer.log(
        agent="security_ai",
        tool="risk.unknown_device",
        policy_result="ALLOWED",
        permission_level=0,
        execution_status="OK",
        network_id="homelab-default",
        details={
            "kind": "risk_assessment",
            "event_id": event_id,
            "category": category,
            "score": score,
            "rule_id": rule_id,
            "base": 0.5,
            "modifiers": [],
            "reasons": [],
        },
    )


# --- RBAC ------------------------------------------------------------- #

def test_alerts_without_session_redirects_to_login(app):
    c = app.test_client()
    r = c.get("/alerts")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_alerts_viewer_403(app):
    """Auflage 27: viewer hat kein alert.view."""
    c = create_role_client(app, "viewer")
    r = c.get("/alerts")
    assert r.status_code == 403


def test_alerts_system_403(app):
    c = create_role_client(app, "system")
    r = c.get("/alerts")
    assert r.status_code == 403


# --- Happy Path ------------------------------------------------------- #

def test_alerts_operator_empty(app):
    c = create_role_client(app, "operator")
    r = c.get("/alerts")
    assert r.status_code == 200
    assert "Keine Alarme in den letzten 24 Stunden".encode() in r.data


def test_alerts_admin_empty(app):
    c = create_role_client(app, "admin")
    r = c.get("/alerts")
    assert r.status_code == 200


def test_alerts_shows_assessment(app):
    _write_assessment(app, category="CONFIRMED")
    c = create_role_client(app, "admin")
    r = c.get("/alerts")
    assert r.status_code == 200
    assert b"CONFIRMED" in r.data
    assert b"unknown_device" in r.data
    assert b"EVT-2026-09-22-deadbeef" in r.data


# --- Auflage 26: Badge mit Text, Farbe korrekt ------------------------ #

@pytest.mark.parametrize("category,badge_class", [
    ("SECURITY_ALERT", "badge-red"),
    ("CONFIRMED", "badge-red"),
    ("SUSPICION", "badge-yellow"),
    ("ANOMALY", "badge-cyan"),
    ("EVENT", "badge-cyan"),
])
def test_alerts_badge_mapping(app, category, badge_class):
    _write_assessment(app, category=category)
    c = create_role_client(app, "admin")
    r = c.get("/alerts")
    assert r.status_code == 200
    # Badge-Klasse korrekt
    assert badge_class.encode() in r.data
    # Kategorie-Text sichtbar (Auflage 26)
    assert category.encode() in r.data


# --- Auflage 28: unbekannte Kategorie -------------------------------- #

def test_alerts_unknown_category_shown(app):
    _write_assessment(app, category="LEGACY_FOO")
    c = create_role_client(app, "admin")
    r = c.get("/alerts")
    assert r.status_code == 200
    # Nicht verschluckt
    assert b"LEGACY_FOO" in r.data
    # badge-cyan als Fallback
    assert b"badge-cyan" in r.data


# --- XSS -------------------------------------------------------------- #

def test_alerts_escapes_xss_in_category(app):
    payload = "<img src=x onerror=alert(1)>"
    _write_assessment(app, category=payload)
    c = create_role_client(app, "admin")
    r = c.get("/alerts")
    assert r.status_code == 200
    assert b"<img src=x" not in r.data
    assert b"&lt;img src=x onerror=alert(1)&gt;" in r.data


# --- CSP -------------------------------------------------------------- #

def test_alerts_csp_header_present(app):
    c = create_role_client(app, "admin")
    r = c.get("/alerts")
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp


# --- Auflage 29: kein tojson, kein JS --------------------------------- #

def test_alerts_no_json_blob_in_body(app):
    _write_assessment(app, category="CONFIRMED")
    c = create_role_client(app, "admin")
    r = c.get("/alerts")
    # Kein |tojson-Output (waere JSON-Objekt mit geschweiften
    # Klammern und Quotes um Feldnamen).
    assert b'"category"' not in r.data
    assert b'"audit_id"' not in r.data
