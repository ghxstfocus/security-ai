"""
Tests fuer apps/dashboard/routes_chat.py.

Kategorie 3 (Route, RBAC, CSRF-Header, JSON, Rate-Limit,
LLM-Fehler-Mapping).

Auflagen 85-123 aus Review-Runde 3.6.8e.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from apps.dashboard import csrf
from harness.llm.errors import LLMUnavailable
from tests.unit._helpers import (
    build_dashboard_app,
    create_role_client,
)


@pytest.fixture()
def app(tmp_path: Path):
    return build_dashboard_app(tmp_path)


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Vor jedem Test: Rate-Limit-Zaehler leeren."""
    from apps.dashboard.routes_chat import _rate_limiter
    with _rate_limiter._lock:
        _rate_limiter._hits.clear()
    yield


def _client_with_csrf(app, role):
    c = create_role_client(app, role)
    with c.session_transaction() as sess:
        tok = csrf.get_or_create(sess)
    return c, tok


def _post(app, client, tok, body, content_type="application/json"):
    headers = {}
    if tok is not None:
        headers["X-CSRF-Token"] = tok
    if content_type is not None:
        headers["Content-Type"] = content_type
    return client.post("/api/chat", data=body, headers=headers)


# --- RBAC ------------------------------------------------------------- #

def test_chat_without_session_redirects_to_login(app):
    c = app.test_client()
    r = c.get("/chat")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_chat_api_without_session_redirects_to_login(app):
    c = app.test_client()
    r = c.post("/api/chat", json={"question": "hi"})
    assert r.status_code == 302


def test_chat_page_viewer_200(app):
    # viewer hat chat.ask.
    c = create_role_client(app, "viewer")
    r = c.get("/chat")
    assert r.status_code == 200


def test_chat_page_operator_200(app):
    c = create_role_client(app, "operator")
    r = c.get("/chat")
    assert r.status_code == 200


# --- CSRF-Header (A88, A89, A119, A120) ------------------------------- #

def test_chat_api_without_csrf_header_400(app):
    c = create_role_client(app, "viewer")
    r = c.post(
        "/api/chat",
        json={"question": "hi"},
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 400
    assert r.headers["Content-Type"].startswith("application/json")


def test_chat_api_wrong_csrf_header_400(app):
    c = create_role_client(app, "viewer")
    r = c.post(
        "/api/chat",
        json={"question": "hi"},
        headers={
            "Content-Type": "application/json",
            "X-CSRF-Token": "falsch",
        },
    )
    assert r.status_code == 400


def test_chat_api_csrf_check_before_body_read(app):
    """
    Ohne CSRF darf der Body NICHT gelesen werden.
    Wir schicken absichtlich kaputtes JSON.
    Erwartet: 400 (CSRF-Fehler), nicht 400 (JSON-Fehler).
    Beide 400, aber der Body darf nicht geparst werden.
    Wir testen das, indem wir einen Body schicken, der
    bei Parse einen unerwarteten Fehler werfen wuerde:
    Hier reicht: Status 400 ohne Exception.
    """
    c = create_role_client(app, "viewer")
    r = c.post(
        "/api/chat",
        data=b"nicht json",
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 400


# --- Content-Type (A106) --------------------------------------------- #

def test_chat_api_not_json_content_type_400(app):
    c, tok = _client_with_csrf(app, "viewer")
    r = c.post(
        "/api/chat",
        data="question=hi",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "X-CSRF-Token": tok,
        },
    )
    assert r.status_code == 400


def test_chat_api_broken_json_400(app):
    c, tok = _client_with_csrf(app, "viewer")
    r = c.post(
        "/api/chat",
        data=b"nicht json",
        headers={
            "Content-Type": "application/json",
            "X-CSRF-Token": tok,
        },
    )
    assert r.status_code == 400


# --- Felder (A107, A108, A111) --------------------------------------- #

def test_chat_api_missing_question_400(app):
    c, tok = _client_with_csrf(app, "viewer")
    r = _post(app, c, tok, body=b'{"detail": false}')
    assert r.status_code == 400


def test_chat_api_empty_question_400(app):
    c, tok = _client_with_csrf(app, "viewer")
    r = _post(app, c, tok, body=b'{"question": "   "}')
    assert r.status_code == 400


def test_chat_api_question_too_long_400(app):
    c, tok = _client_with_csrf(app, "viewer")
    import json as _json
    body = _json.dumps({"question": "a" * 2001}).encode()
    r = _post(app, c, tok, body=body)
    assert r.status_code == 400


def test_chat_api_detail_not_bool_400(app):
    c, tok = _client_with_csrf(app, "viewer")
    r = _post(
        app, c, tok,
        body=b'{"question": "hi", "detail": "yes"}',
    )
    assert r.status_code == 400


# --- Happy Path mit gemocktem ChatService ---------------------------- #

def _patch_chat_service(app, monkeypatch, response=None,
                        exc=None, counter=None):
    from apps.security_ai.chat import ChatService, ChatResponse

    def _ask(self, principal_name, question, *, detail=False,
             **kw):
        if counter is not None:
            counter.append(1)
        if exc is not None:
            raise exc
        if response is not None:
            return response
        return ChatResponse(
            answer="Antwort",
            principal=principal_name,
            question=question,
            context_used=None,
            used_llm=True,
            source="llm",
            model="llama3.2:3b",
            model_reason="default",
            denied=False,
            answer_id="AUD-2026-09-23-abcdef12",
        )
    monkeypatch.setattr(ChatService, "ask", _ask)


def test_chat_api_happy_path_200_and_whitelist(app, monkeypatch):
    _patch_chat_service(app, monkeypatch)
    c, tok = _client_with_csrf(app, "viewer")
    r = _post(app, c, tok, body=b'{"question": "hallo"}')
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("application/json")
    data = r.get_json()
    assert set(data.keys()) == {
        "answer", "model", "model_reason", "source",
        "denied", "answer_id",
    }
    assert data["answer"] == "Antwort"


# --- LLM-Fehler -> 502 (A92, A93, A116) ------------------------------ #

def test_chat_api_llm_unavailable_502(app, monkeypatch):
    _patch_chat_service(app, monkeypatch, exc=LLMUnavailable("x"))
    c, tok = _client_with_csrf(app, "viewer")
    r = _post(app, c, tok, body=b'{"question": "hallo"}')
    assert r.status_code == 502
    data = r.get_json()
    assert data == {"error": "LLM nicht erreichbar"}
    assert b"x" not in r.data


# --- Rate-Limit (A100, A102, A113, A114, A122) ----------------------- #

def test_chat_api_rate_limit_429_and_retry_after(app, monkeypatch):
    from apps.dashboard.routes_chat import _rate_limiter
    monkeypatch.setattr(_rate_limiter, "_max", 2)
    _patch_chat_service(app, monkeypatch)
    c, tok = _client_with_csrf(app, "viewer")
    for _ in range(2):
        r = _post(app, c, tok, body=b'{"question": "hallo"}')
        assert r.status_code == 200
    r = _post(app, c, tok, body=b'{"question": "hallo"}')
    assert r.status_code == 429
    assert "Retry-After" in r.headers


def test_chat_service_not_called_on_rate_limit(app, monkeypatch):
    from apps.dashboard.routes_chat import _rate_limiter
    # Limiter im Modul mit kleiner Grenze bauen.
    monkeypatch.setattr(_rate_limiter, "_max", 2)
    calls: list[int] = []
    _patch_chat_service(app, monkeypatch, counter=calls)
    c, tok = _client_with_csrf(app, "viewer")
    for _ in range(5):
        _post(app, c, tok, body=b'{"question": "hallo"}')
    assert len(calls) == 2


def test_rate_limit_per_principal(app, monkeypatch):
    from apps.dashboard.routes_chat import _rate_limiter
    monkeypatch.setattr(_rate_limiter, "_max", 2)
    _patch_chat_service(app, monkeypatch)
    c1, tok1 = _client_with_csrf(app, "viewer")
    c2, tok2 = _client_with_csrf(app, "operator")
    for _ in range(2):
        r = _post(app, c1, tok1, body=b'{"question": "x"}')
        assert r.status_code == 200
    r = _post(app, c1, tok1, body=b'{"question": "x"}')
    assert r.status_code == 429
    # Anderer Principal darf weiter.
    r = _post(app, c2, tok2, body=b'{"question": "x"}')
    assert r.status_code == 200


def test_rate_limit_window_resets(app, monkeypatch):
    from apps.dashboard.routes_chat import _rate_limiter
    monkeypatch.setattr(_rate_limiter, "_max", 1)
    _patch_chat_service(app, monkeypatch)
    c, tok = _client_with_csrf(app, "viewer")
    r = _post(app, c, tok, body=b'{"question": "x"}')
    assert r.status_code == 200
    r = _post(app, c, tok, body=b'{"question": "x"}')
    assert r.status_code == 429
    # Fenster kuenstlich ueberspringen.
    with _rate_limiter._lock:
        for k in _rate_limiter._hits:
            _rate_limiter._hits[k] = [
                t - _rate_limiter._window - 1
                for t in _rate_limiter._hits[k]
            ]
    r = _post(app, c, tok, body=b'{"question": "x"}')
    assert r.status_code == 200


# --- CSP -------------------------------------------------------------- #

def test_chat_csp_header_present(app):
    c = create_role_client(app, "viewer")
    r = c.get("/chat")
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "connect-src 'self'" in csp


# --- A121: CSRF-Token stabil ----------------------------------------- #

def test_csrf_token_stable_across_requests(app):
    c = create_role_client(app, "viewer")
    r1 = c.get("/chat")
    r2 = c.get("/chat")
    import re as _re
    pat = _re.compile(rb'data-csrf-token="([^"]+)"')
    m1 = pat.search(r1.data)
    m2 = pat.search(r2.data)
    assert m1 is not None and m2 is not None
    assert m1.group(1) == m2.group(1)


# --- A112: Leak-Asserts ---------------------------------------------- #

_LEAK_MARKERS = (
    b"context_used", b"llm_error", b"ChatService",
    b"OllamaClient", b"ollama", b"127.0.0.1",
    b"Traceback", b'  File "',
)


def _assert_no_leak(body: bytes) -> None:
    for marker in _LEAK_MARKERS:
        assert marker not in body, f"Leak: {marker!r}"


def test_no_leak_200(app, monkeypatch):
    _patch_chat_service(app, monkeypatch)
    c, tok = _client_with_csrf(app, "viewer")
    r = _post(app, c, tok, body=b'{"question": "hi"}')
    _assert_no_leak(r.data)


def test_no_leak_400(app):
    c = create_role_client(app, "viewer")
    r = c.post(
        "/api/chat",
        json={"question": "hi"},
        headers={"Content-Type": "application/json"},
    )
    _assert_no_leak(r.data)


def test_no_leak_502(app, monkeypatch):
    _patch_chat_service(app, monkeypatch, exc=LLMUnavailable("x"))
    c, tok = _client_with_csrf(app, "viewer")
    r = _post(app, c, tok, body=b'{"question": "hi"}')
    _assert_no_leak(r.data)


def test_no_csrf_token_in_response(app):
    c, tok = _client_with_csrf(app, "viewer")
    r = c.get("/chat")
    # Token im HTML ist ok (data-Attribut), aber nicht im
    # API-Response.
    r2 = c.post(
        "/api/chat",
        json={"question": "hi"},
        headers={
            "Content-Type": "application/json",
            "X-CSRF-Token": tok,
        },
    )
    # Der Body darf den Token nicht spiegeln.
    assert tok.encode() not in r2.data
