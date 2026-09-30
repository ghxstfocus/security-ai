"""
Dashboard-Routen fuer den Chat.

Kategorie 3: Route uebernimmt RBAC, Input, Output,
LLM-Fehler-Mapping, weil ChatService kein ServiceError-
Modell nutzt (ARCHITECTURE §3.17).

- GET  /chat       chat.ask (Seite)
- POST /api/chat   chat.ask (JSON)

CSRF: Header X-CSRF-Token (Auflage 88).
Reihenfolge im POST (Auflage 119):
  1. CSRF-Header pruefen (liest NICHTS aus dem Body).
  2. Content-Type pruefen (request.is_json).
  3. JSON parsen (silent=True + None-Check).
  4. Pflichtfelder/Laengen.
  5. Rate-Limit (pro Principal).
  6. RBAC (via ChatService.ask).
  7. LLM-Aufruf.

Fehler:
- CSRF fehlt/falsch     -> 400 JSON.
- Kein application/json -> 400 JSON.
- JSON kaputt           -> 400 JSON.
- question fehlt/leer/zu lang -> 400 JSON.
- Rate-Limit erreicht   -> 429 JSON + Retry-After.
- AccessDeniedError     -> 403 JSON.
- LLMError/Timeout/Unavailable -> 502 JSON (Auflage 487).
- ChatServiceError      -> 400 JSON.
- ChatOperationError    -> NICHT fangen (globaler 500).

Response 200: genau 6 Schluessel (Auflage 91):
  answer, model, model_reason, source, denied, answer_id.
"""
from __future__ import annotations

from typing import Any

from flask import Flask, Response, g, jsonify, render_template, request

from apps.dashboard.decorators import require_permission
from apps.security_ai.chat import (
    ChatOperationError,
    ChatService,
    ChatServiceError,
)
from core.context.builder import build_chat_context
from core.context.links import extract_links
from core.services.rate_limit_service import RateLimitService
from harness.llm.errors import LLMError, LLMTimeout, LLMUnavailable

QUESTION_MAX_LEN = 2000


def _build_chat_service() -> ChatService:
    from harness.llm.client import OllamaClient
    return ChatService(
        audit_writer=g.audit,
        llm_client=OllamaClient(),
        checker=g.access_checker,
    )


def _json_error(message: str, status: int, **headers: Any) -> Response:
    resp = jsonify({"error": message})
    resp.status_code = status
    for k, v in headers.items():
        resp.headers[k] = v
    return resp


def register_chat_routes(app: Flask) -> None:
    @app.route("/chat", methods=["GET"])
    @require_permission("chat.ask")
    def chat_page() -> str:
        perms = g.access_checker.permissions_of(g.principal)
        return render_template(
            "chat.html",
            page_title="Chat",
            can_deep=("chat.detail" in perms),
        )

    @app.route("/api/chat", methods=["POST"])
    @require_permission("chat.ask")
    def chat_api() -> Response:
        # 1. CSRF-Header (liest NICHTS aus dem Body)
        submitted = request.headers.get("X-CSRF-Token")
        from flask import session
        expected = session.get("_csrf_token")
        from apps.dashboard import csrf
        if not csrf.validate(submitted, expected):
            return _json_error("Ungueltige Anfrage", 400)

        # 2. Content-Type
        if not request.is_json:
            return _json_error("Ungueltige Anfrage", 400)

        # 3. JSON parsen
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return _json_error("Ungueltige Anfrage", 400)

        # 4. Felder
        question = payload.get("question")
        if not isinstance(question, str):
            return _json_error("Ungueltige Anfrage", 400)
        q = question.strip()
        if not q or len(q) > QUESTION_MAX_LEN:
            return _json_error("Ungueltige Anfrage", 400)

        detail_raw = payload.get("detail", False)
        if not isinstance(detail_raw, bool):
            return _json_error("Ungueltige Anfrage", 400)
        detail = detail_raw

        # 5. Rate-Limit (Punkt 9: SQLite-basiert,
        # Multi-Worker-fest; pro Request mit g.conn).
        from flask import current_app
        rate_limiter = RateLimitService(
            g.conn,
            window_seconds=current_app.config["CHAT_RATE_WINDOW"],
            max_requests=current_app.config["CHAT_RATE_MAX"],
        )
        allowed, retry_after = rate_limiter.allow(g.principal)
        if not allowed:
            return _json_error(
                "Zu viele Anfragen", 429,
                **{"Retry-After": str(retry_after)},
            )

        # 6. + 7. RBAC + LLM via ChatService
        # Punkt 28 (A725): Kontext aus DB + audit-logs
        # bauen. Gemeinsamer Builder (core/context/builder).
        ctx = build_chat_context(
            g.conn, current_app.config["AUDIT_BASE_DIR"],
        )
        # ctx ist dict[str, object] (build_chat_context).
        # Guards fuer die zwei Werte, die mypy als object
        # sieht und die ChatService.ask typisiert erwartet
        # (dict[str, Any] | None bzw. int). Fail closed.
        snapshot_raw = ctx["inventory_snapshot"]
        if not isinstance(snapshot_raw, dict):
            return _json_error("Ungueltige Anfrage", 400)
        since_raw = ctx["since_hours"]
        if not isinstance(since_raw, int):
            return _json_error("Ungueltige Anfrage", 400)
        service = _build_chat_service()
        try:
            resp = service.ask(
                g.principal, q,
                risk_assessments=ctx["risk_assessments"],
                inventory_snapshot=snapshot_raw,
                open_approvals=ctx["open_approvals"],
                open_changes=ctx["open_changes"],
                log_excerpts=ctx["log_excerpts"],
                recent_events=ctx["recent_events"],
                since_hours=since_raw,
                detail=detail,
            )
        except LLMTimeout:
            return _json_error("LLM nicht erreichbar", 502)
        except LLMUnavailable:
            return _json_error("LLM nicht erreichbar", 502)
        except LLMError:
            return _json_error("LLM nicht erreichbar", 502)
        except ChatOperationError:
            raise
        except ChatServiceError:
            return _json_error("Ungueltige Anfrage", 400)
        except Exception as exc:
            from core.access.checker import AccessDeniedError
            if isinstance(exc, AccessDeniedError):
                return _json_error("Zugriff verweigert", 403)
            raise

        # Punkt 30 (A757/A758): Links nur im
        # fact/detail_append-Pfad (deterministisch).
        # LLM-Antworten werden nicht durchsucht.
        links: list[dict] = []
        if resp.source in ("fact", "detail_append"):
            links = extract_links(
                resp.answer, g.principal, g.access_checker,
            )
        body = {
            "answer": resp.answer,
            "model": resp.model,
            "model_reason": resp.model_reason,
            "source": resp.source,
            "denied": bool(resp.denied),
            "answer_id": resp.answer_id,
            "links": links,
            "nav_links": list(resp.nav_links),
        }
        return jsonify(body)


__all__ = ["QUESTION_MAX_LEN", "register_chat_routes"]
