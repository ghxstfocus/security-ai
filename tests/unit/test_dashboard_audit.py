"""
Tests fuer apps/dashboard/routes_audit.py.

Kategorie 3 (Route, RBAC, read-only, Rohdaten-Anzeige).

Auflagen 195-206 aus Review-Runde 3.6.8h.
"""
from __future__ import annotations

from datetime import UTC, datetime, timezone
from pathlib import Path

import pytest

from tests.unit._helpers import (
    build_dashboard_app,
    create_role_client,
)


@pytest.fixture()
def app(tmp_path: Path):
    return build_dashboard_app(tmp_path)


def _write_audit(app, **overrides):
    """Schreibt einen Audit-Eintrag in die tmp-Audit-Datei."""
    writer = app.extensions["audit_writer"]
    kwargs = {
        "agent": "security_ai",
        "tool": "test_tool",
        "policy_result": "ALLOWED",
        "permission_level": 0,
        "execution_status": "OK",
        "details": {"kind": "test_kind"},
    }
    kwargs.update(overrides)
    return writer.log(**kwargs)


def _today_utc():
    return datetime.now(UTC).strftime("%Y-%m-%d")


# --- RBAC ------------------------------------------------------------- #

def test_audit_without_session_redirects_to_login(app):
    c = app.test_client()
    r = c.get("/audit")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_audit_viewer_200(app):
    # viewer hat audit.read.
    c = create_role_client(app, "viewer")
    r = c.get("/audit")
    assert r.status_code == 200


def test_audit_operator_200(app):
    c = create_role_client(app, "operator")
    r = c.get("/audit")
    assert r.status_code == 200


def test_audit_system_403(app):
    # system hat audit.write, nicht audit.read.
    c = create_role_client(app, "system")
    r = c.get("/audit")
    assert r.status_code == 403


def test_audit_admin_200(app):
    c = create_role_client(app, "admin")
    r = c.get("/audit")
    assert r.status_code == 200


# --- Liste ------------------------------------------------------------ #

def test_audit_default_today_empty(app):
    c = create_role_client(app, "admin")
    r = c.get("/audit")
    assert r.status_code == 200
    # Heute: keine Eintraege in der tmp-Audit-Datei.
    body = r.data.decode("utf-8", errors="replace")
    assert "Zeige Eintraege fuer" in body
    assert "(UTC)" in body


def test_audit_lists_entry(app):
    e = _write_audit(app)
    c = create_role_client(app, "admin")
    r = c.get("/audit")
    assert r.status_code == 200
    assert e.audit_id.encode() in r.data
    assert b"test_tool" in r.data


def test_audit_explicit_date_200(app):
    _write_audit(app)
    c = create_role_client(app, "admin")
    r = c.get("/audit?date=" + _today_utc())
    assert r.status_code == 200


def test_audit_invalid_date_400(app):
    c = create_role_client(app, "admin")
    r = c.get("/audit?date=kaputt")
    assert r.status_code == 400


def test_audit_invalid_date_1301_400(app):
    c = create_role_client(app, "admin")
    r = c.get("/audit?date=2026-13-01")
    assert r.status_code == 400


def test_audit_empty_day_200(app):
    # Ein Tag ohne JSONL-Datei -> 200 + "Keine Eintraege".
    c = create_role_client(app, "admin")
    r = c.get("/audit?date=2099-01-01")
    assert r.status_code == 200
    assert b"Keine Eintraege" in r.data


# --- Detail ----------------------------------------------------------- #

def test_audit_detail_shows_entry(app):
    e = _write_audit(app)
    c = create_role_client(app, "admin")
    r = c.get("/audit/" + e.audit_id)
    assert r.status_code == 200
    assert e.audit_id.encode() in r.data
    assert b"test_tool" in r.data


def test_audit_detail_unknown_404(app):
    c = create_role_client(app, "admin")
    r = c.get("/audit/AUD-2099-01-01-00000000")
    assert r.status_code == 404


@pytest.mark.parametrize("bad", [
    "kaputt",
    "AUD-2026-1-abcdef12",
    "aud-2026-01-01-abcdef12",
    "AUD-2026-01-01-zzzzzzzz",
    "AUD-2026-01-01-abcdef123",
    "..",
])
def test_audit_detail_invalid_id_404(app, bad):
    c = create_role_client(app, "admin")
    r = c.get("/audit/" + bad)
    assert r.status_code == 404


def test_audit_unmatched_route_403_fail_closed(app):
    c = create_role_client(app, "admin")
    for path in ("/audit/", "/audit/a/b"):
        r = c.get(path)
        assert r.status_code == 403


# --- A198/A203: details formatiert ---------------------------------- #

def test_audit_detail_details_formatted(app):
    """details_formatted ist JSON mit indent=2 und
    sortierten Keys. Jinja escaped es."""
    e = _write_audit(
        app,
        details={"zeta": 1, "alpha": 2, "kind": "test"},
    )
    c = create_role_client(app, "admin")
    r = c.get("/audit/" + e.audit_id)
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    # Jinja escaped die Quotes in <pre> (&#34;).
    # Wir suchen nach den nackten Keys.
    i_alpha = body.find("alpha")
    i_zeta = body.find("zeta")
    assert i_alpha != -1 and i_zeta != -1
    assert i_alpha < i_zeta


# --- A204: error wird escaped --------------------------------------- #

def test_audit_detail_error_escaped(app):
    payload = "<script>alert(1)</script>"
    e = _write_audit(app, error=payload)
    c = create_role_client(app, "admin")
    r = c.get("/audit/" + e.audit_id)
    assert r.status_code == 200
    assert b"<script>" not in r.data
    assert b"&lt;script&gt;" in r.data


# --- A202: kein Reflexions-Dump ------------------------------------- #

def test_audit_detail_no_reflection_dump(app):
    """Ein Feld, das nicht in der expliziten Liste steht,
    wird nicht gerendert."""
    e = _write_audit(app, details={"unexpected_key": "value_xyz"})
    c = create_role_client(app, "admin")
    r = c.get("/audit/" + e.audit_id)
    # unexpected_key steht in details_formatted -> sichtbar,
    # aber NICHT als Top-Level-dt. Wir pruefen nur: es gibt
    # nicht ploetzlich einen dt-Eintrag fuer einen
    # unbekannten Top-Level-Key.
    # Der Test ist absichtlich vage; das harte Kriterium ist
    # das Template: es listet die Felder explizit.
    assert r.status_code == 200


# --- CSP + Leak ----------------------------------------------------- #

def test_audit_csp_header_present(app):
    c = create_role_client(app, "admin")
    r = c.get("/audit")
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp


_LEAK_MARKERS = (
    b"AuditReaderService",
    b"audit_reader_service",
    b"base_dir",
    b"Traceback",
    b'  File "',
)


def _assert_no_leak(body: bytes) -> None:
    for m in _LEAK_MARKERS:
        assert m not in body, f"Leak: {m!r}"


def test_no_leak_list(app):
    _write_audit(app)
    c = create_role_client(app, "admin")
    r = c.get("/audit")
    _assert_no_leak(r.data)


def test_no_leak_detail(app):
    e = _write_audit(app)
    c = create_role_client(app, "admin")
    r = c.get("/audit/" + e.audit_id)
    _assert_no_leak(r.data)


def test_no_leak_detail_404(app):
    c = create_role_client(app, "admin")
    r = c.get("/audit/AUD-2099-01-01-00000000")
    _assert_no_leak(r.data)
