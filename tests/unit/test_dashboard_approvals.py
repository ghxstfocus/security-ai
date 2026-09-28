"""
Tests fuer apps/dashboard/routes_approvals.py.

Kategorie 3 (Route, RBAC, CSRF, Template).

Auflagen 34-48 aus Review-Runde 3.6.8c.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from core.approval.models import ApprovalStatus
from core.approval.repository import ApprovalRepository
from core.inventory.repository import connect
from tests.unit._helpers import (
    build_dashboard_app,
    create_role_client,
)


@pytest.fixture()
def app(tmp_path: Path):
    return build_dashboard_app(tmp_path)


def _seed_approval(app, *, tool_name="nmap_scan"):
    conn = connect(app.config["DB_PATH"])
    try:
        repo = ApprovalRepository(conn)
        req = repo.create(
            tool_name=tool_name,
            args={"target": "10.0.0.1"},
            requested_by="security_ai",
            reason="Port-Scan im Hauptnetz",
            risk_category="SECURITY_ALERT",
            risk_score=0.7,
        )
        return req.request_id
    finally:
        conn.close()


def _get_status(app, request_id):
    conn = connect(app.config["DB_PATH"])
    try:
        return ApprovalRepository(conn).get(request_id).status
    finally:
        conn.close()


def _client_with_csrf(app, role):
    """Login-Client mit gueltigem CSRF-Token in der Session.

    Kein GET /approvals, damit der Helper auch fuer Rollen
    ohne approval.view funktioniert (Auflage 50).
    """
    from apps.dashboard import csrf
    c = create_role_client(app, role)
    with c.session_transaction() as sess:
        tok = csrf.get_or_create(sess)
    return c, tok


# --- RBAC ------------------------------------------------------------- #

def test_approvals_without_session_redirects_to_login(app):
    c = app.test_client()
    r = c.get("/approvals")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_approvals_viewer_403(app):
    c = create_role_client(app, "viewer")
    r = c.get("/approvals")
    assert r.status_code == 403


def test_approvals_system_403(app):
    c = create_role_client(app, "system")
    r = c.get("/approvals")
    assert r.status_code == 403


def test_approvals_operator_empty(app):
    c = create_role_client(app, "operator")
    r = c.get("/approvals")
    assert r.status_code == 200
    assert b"Keine offenen Approvals" in r.data


def test_approvals_admin_lists_pending(app):
    rid = _seed_approval(app)
    c = create_role_client(app, "admin")
    r = c.get("/approvals")
    assert r.status_code == 200
    assert rid.encode() in r.data
    assert b"pending" in r.data


# --- Detail ----------------------------------------------------------- #

def test_approval_detail_shows_entry(app):
    rid = _seed_approval(app)
    c = create_role_client(app, "admin")
    r = c.get("/approvals/" + rid)
    assert r.status_code == 200
    assert rid.encode() in r.data
    assert b"nmap_scan" in r.data


def test_approval_detail_unknown_404(app):
    c = create_role_client(app, "admin")
    r = c.get("/approvals/APR-2099-99999")
    assert r.status_code == 404


@pytest.mark.parametrize("bad", [
    "APR-2026-1",
    "APR-26-00001",
    "april-2026-00001",
    "APR-2026-00001x",
    "..",
])
def test_approval_detail_invalid_id_404(app, bad):
    c = create_role_client(app, "admin")
    r = c.get("/approvals/" + bad)
    assert r.status_code == 404


def test_approval_unmatched_route_403_fail_closed(app):
    """
    Pfade ohne View mit _required_permission -> 403
    (fail closed). Analog 3.6.8a.
    """
    c = create_role_client(app, "admin")
    for path in ("/approvals/", "/approvals/x/y"):
        r = c.get(path)
        assert r.status_code == 403


# --- POST decide: CSRF + Whitelist ------------------------------------ #

def test_decide_without_csrf_400(app):
    rid = _seed_approval(app)
    c = create_role_client(app, "operator")
    r = c.post(
        f"/approvals/{rid}/decide",
        data={"decision": "granted"},
    )
    assert r.status_code == 400


def test_decide_with_wrong_csrf_400(app):
    rid = _seed_approval(app)
    c, _tok = _client_with_csrf(app, "operator")
    r = c.post(
        f"/approvals/{rid}/decide",
        data={"_csrf_token": "falsch", "decision": "granted"},
    )
    assert r.status_code == 400


def test_decide_invalid_decision_400(app):
    rid = _seed_approval(app)
    c, tok = _client_with_csrf(app, "operator")
    r = c.post(
        f"/approvals/{rid}/decide",
        data={"_csrf_token": tok, "decision": "maybe"},
    )
    assert r.status_code == 400


def test_decide_reason_too_long_400(app):
    rid = _seed_approval(app)
    c, tok = _client_with_csrf(app, "operator")
    r = c.post(
        f"/approvals/{rid}/decide",
        data={
            "_csrf_token": tok,
            "decision": "granted",
            "reason": "x" * 501,
        },
    )
    assert r.status_code == 400


# --- POST decide: Happy Path ------------------------------------------ #

def test_decide_granted_302_and_db_status(app):
    rid = _seed_approval(app)
    c, tok = _client_with_csrf(app, "operator")
    r = c.post(
        f"/approvals/{rid}/decide",
        data={"_csrf_token": tok, "decision": "granted",
              "reason": "ok"},
    )
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/approvals")
    assert _get_status(app, rid) is ApprovalStatus.GRANTED


def test_decide_rejected_302_and_db_status(app):
    rid = _seed_approval(app)
    c, tok = _client_with_csrf(app, "operator")
    r = c.post(
        f"/approvals/{rid}/decide",
        data={"_csrf_token": tok, "decision": "rejected"},
    )
    assert r.status_code == 302
    assert _get_status(app, rid) is ApprovalStatus.REJECTED


# --- Auflage 44: zweimal entscheiden ---------------------------------- #

def test_decide_twice_granted_then_granted_409(app):
    rid = _seed_approval(app)
    c, tok = _client_with_csrf(app, "operator")
    c.post(f"/approvals/{rid}/decide",
           data={"_csrf_token": tok, "decision": "granted"})
    r = c.post(f"/approvals/{rid}/decide",
               data={"_csrf_token": tok, "decision": "granted"})
    # Auflage 489/505: doppelte Entscheidung = Zustandskonflikt.
    assert r.status_code == 409


def test_decide_twice_granted_then_rejected_409(app):
    rid = _seed_approval(app)
    c, tok = _client_with_csrf(app, "operator")
    c.post(f"/approvals/{rid}/decide",
           data={"_csrf_token": tok, "decision": "granted"})
    r = c.post(f"/approvals/{rid}/decide",
               data={"_csrf_token": tok, "decision": "rejected"})
    # Auflage 489/505: bereits entschieden -> Zustandskonflikt.
    assert r.status_code == 409


# --- RBAC auf POST ---------------------------------------------------- #

def test_decide_viewer_with_valid_csrf_still_403(app):
    rid = _seed_approval(app)
    c, tok = _client_with_csrf(app, "viewer")
    assert tok  # CSRF-Token vorhanden
    # RBAC greift im before_request VOR dem CSRF-Check:
    # viewer hat kein approval.decide -> 403.
    r = c.post(
        f"/approvals/{rid}/decide",
        data={"_csrf_token": tok, "decision": "granted"},
    )
    assert r.status_code == 403


# --- XSS ------------------------------------------------------------- #

def test_decide_reason_xss_escaped_on_detail(app):
    rid = _seed_approval(app)
    c, tok = _client_with_csrf(app, "operator")
    payload = "<img src=x onerror=alert(1)>"
    c.post(f"/approvals/{rid}/decide",
           data={"_csrf_token": tok, "decision": "rejected",
                 "reason": payload})
    # Detail nach Entscheidung zeigt decision_reason escaped.
    r = c.get("/approvals/" + rid)
    assert r.status_code == 200
    assert b"<img src=x" not in r.data
    assert b"&lt;img src=x onerror=alert(1)&gt;" in r.data


# --- CSP ------------------------------------------------------------- #

def test_approvals_csp_header_present(app):
    c = create_role_client(app, "admin")
    r = c.get("/approvals")
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp


# --- Auflage 48: kein Leak im Body ----------------------------------- #

def test_no_internal_leak_in_body(app):
    rid = _seed_approval(app)
    c, tok = _client_with_csrf(app, "admin")
    r = c.get("/approvals/" + rid)
    body = r.data
    assert b"ApprovalQueue" not in body
    assert b"harness.approval" not in body
    assert b"from harness" not in body
    assert b"approval_service" not in body
    assert b"Traceback" not in body
    assert b'File "' not in body


def test_no_internal_leak_on_404(app):
    c = create_role_client(app, "admin")
    r = c.get("/approvals/APR-2099-99999")
    assert r.status_code == 404
    body = r.data
    assert b"ApprovalQueue" not in body
    assert b"harness.approval" not in body
    assert b"approval_service" not in body
    assert b"Traceback" not in body
    assert b'File "' not in body

# --- 3.6.15c Auflage 505: neue Faelle ------------------------------ #

def test_decide_unknown_returns_404(app):
    c, tok = _client_with_csrf(app, "operator")
    r = c.post(
        "/approvals/APR-2026-99999/decide",
        data={"_csrf_token": tok, "decision": "granted"},
    )
    assert r.status_code == 404


def test_decide_invalid_id_returns_400(app):
    # Auflage 504: Format -> ApprovalServiceError -> 400.
    c, tok = _client_with_csrf(app, "operator")
    r = c.post(
        "/approvals/UNGUELTIG/decide",
        data={"_csrf_token": tok, "decision": "granted"},
    )
    assert r.status_code == 400


def test_repository_error_returns_500(app, monkeypatch):
    from core.approval.repository import ApprovalRepositoryError
    from harness.approval.queue import ApprovalQueue

    rid = _seed_approval(app)

    def _boom(self, *a, **kw):
        raise ApprovalRepositoryError("db kaputt")

    monkeypatch.setattr(ApprovalQueue, "grant", _boom)
    c, tok = _client_with_csrf(app, "operator")
    r = c.post(
        f"/approvals/{rid}/decide",
        data={"_csrf_token": tok, "decision": "granted"},
    )
    # Auflage 504: Basisklasse NICHT fangen -> globaler 500.
    assert r.status_code == 500
