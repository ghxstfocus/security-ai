# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tests fuer apps/dashboard/routes_alerts.py.

Kategorie 3 (Route, RBAC, Template).

Auflagen 26-29 aus Review-Runde 3.6.8b:
- A26 (historisch): Badge-Text war die
  RiskCategory-Rohkategorie (CONFIRMED, SECURITY_ALERT, ...).
- A27: viewer -> 403 (Absicherung gegen spaetere Migration).
- A28: unbekannte Kategorie sichtbar + badge-cyan.
- A29: kein JS, kein |safe, kein tojson.

3.6.14 / Auflage 424: Badge-Text ist das Anzeige-Label
(Info, Hinweis, Warnung, Alarm, Kritisch). Die
Rohkategorie steht nicht mehr im Badge. Die Tests
hier pruefen das Label.
"""
from __future__ import annotations

from pathlib import Path

import pytest

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
    assert b"Keine Alarme in den letzten 24 Stunden" in r.data


def test_alerts_admin_empty(app):
    c = create_role_client(app, "admin")
    r = c.get("/alerts")
    assert r.status_code == 200


def test_alerts_shows_assessment(app):
    _write_assessment(app, category="CONFIRMED")
    c = create_role_client(app, "admin")
    r = c.get("/alerts")
    assert r.status_code == 200
    # 3.6.14 / Auflage 424: Badge zeigt das Anzeige-Label.
    assert b"Kritisch" in r.data
    # Auflage 437: Rohkategorie steht nicht mehr im Body
    # (Bestandsaufnahme: count=0 vor dem Patch).
    assert b"CONFIRMED" not in r.data
    # Punkt 79: rule_id wird in Klartext uebersetzt.
    assert b"Unbekanntes Geraet im Hauptnetz" in r.data
    # Punkt 79: die rohe rule_id steht nicht mehr im Body.
    assert b"unknown_device" not in r.data


# --- Auflage 26: Badge mit Text, Farbe korrekt ------------------------ #

@pytest.mark.parametrize("category,badge_class,label", [
    ("SECURITY_ALERT", "badge-red",    "Alarm"),
    ("CONFIRMED",      "badge-red",    "Kritisch"),
    ("SUSPICION",      "badge-yellow", "Warnung"),
    ("ANOMALY",        "badge-cyan",   "Hinweis"),
    ("EVENT",          "badge-cyan",   "Info"),
])
def test_alerts_badge_mapping(app, category, badge_class, label):
    _write_assessment(app, category=category)
    c = create_role_client(app, "admin")
    r = c.get("/alerts")
    assert r.status_code == 200
    # Badge-Klasse korrekt
    assert badge_class.encode() in r.data
    # Badge-Text ist das Anzeige-Label (3.6.14 / Auflage 424).
    assert label.encode() in r.data
    # Rohkategorie wird NICHT geprueft (Auflage 436): sie
    # steht nicht mehr im Body, ist aber auch kein Erfordernis.


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


# --- Punkt 79: neue Spalten ---

def test_alerts_shows_alert_text(app):
    """Die Spalte "Was" enthaelt Klartext, nicht rule_id."""
    _write_assessment(app, category="CONFIRMED")
    c = create_role_client(app, "admin")
    r = c.get("/alerts")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Was" in body
    assert "Geraet" in body
    assert "Begruendung" in body


def test_alerts_shows_identifier_link_header(app):
    """Die Spalte "Geraet" ist da (8 Spalten)."""
    _write_assessment(app, category="CONFIRMED")
    c = create_role_client(app, "admin")
    r = c.get("/alerts")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    # Punkt 79a: sieben Spalten, Netz in Geraet integriert.
    for header in ("Zeitpunkt", "Was", "Geraet", "IP",
                   "Begruendung", "Bewertung", "Link"):
        assert header in body
    # Netz ist keine eigene Spalte mehr.
    assert "<th>Netz</th>" not in body


def test_alerts_no_link_without_permission(app):
    """Viewer hat kein alert.view -> 403."""
    c = create_role_client(app, "viewer")
    r = c.get("/alerts")
    assert r.status_code == 403
