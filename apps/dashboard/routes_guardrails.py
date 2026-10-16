# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Dashboard-Routen fuer Guardrails (Phase 5).

- GET  /guardrails               guardrail.view   (Seite)
- POST /api/guardrails/<id>/state guardrail.manage (JSON)

Die eigentliche Permission prueft der GuardrailService
(Defense in Depth, DESIGN_DECISIONS Paragraph 11). Der
Decorator markiert die Route nur fuer den
before_request-Check.

list_guardrails ist eine lesende Operation (RBAC ja,
Audit nein). set_state ist schreibend (RBAC ja, Audit ja).

Ablauf POST /api/guardrails/<id>/state:
  1. CSRF-Header (X-CSRF-Token).
  2. Content-Type application/json.
  3. JSON-Body: {"state": "enabled"|"disabled"}.
  4. GuardrailService.set_state(actor, id, state).

Fehler-Mapping:
  Body ungueltig          -> 400 + no-store.
  AccessDeniedError       -> 403 + no-store.
  GuardrailNotFoundError  -> 404 + no-store.
  GuardrailOperationError -> 500 + no-store.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import (
    Flask,
    Response,
    current_app,
    g,
    jsonify,
    render_template,
    request,
    session,
)

from apps.dashboard import csrf
from apps.dashboard.decorators import require_permission
from core.access.checker import AccessDeniedError
from core.guardrails.repository import (
    GuardrailNotFoundError,
    GuardrailRepository,
)
from core.services.guardrail_service import (
    GuardrailOperationError,
    GuardrailService,
)

_ALLOWED_STATES = ("enabled", "disabled")


def _json_error(message: str, status: int) -> Response:
    resp = jsonify({"ok": False, "error": message})
    resp.status_code = status
    resp.headers["Cache-Control"] = "no-store"
    return resp


def register_guardrails_routes(app: Flask) -> None:

    @app.route("/guardrails", methods=["GET"])
    @require_permission("guardrail.view")
    def guardrails_page() -> str:
        repo = GuardrailRepository(
            Path(current_app.config["DB_PATH"])
        )
        service = GuardrailService(
            repo, g.access_checker, g.audit
        )
        guardrails = service.list_guardrails(g.principal)
        return render_template(
            "guardrails.html",
            page_title="Guardrails",
            guardrails=guardrails,
        )

    @app.route(
        "/api/guardrails/<guardrail_id>/state",
        methods=["POST"],
    )
    @require_permission("guardrail.manage")
    def guardrails_set_state(guardrail_id: str) -> Response:
        # 1. CSRF
        submitted = request.headers.get("X-CSRF-Token")
        expected = session.get("_csrf_token")
        if not csrf.validate(submitted, expected):
            return _json_error("Ungueltige Anfrage", 400)

        # 2. Content-Type
        if not request.is_json:
            return _json_error("Ungueltige Anfrage", 400)

        # 3. Body
        payload: Any = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return _json_error("Ungueltige Anfrage", 400)
        state = payload.get("state")
        if not isinstance(state, str) or state not in _ALLOWED_STATES:
            return _json_error("Ungueltige Anfrage", 400)

        # 4. Service
        repo = GuardrailRepository(
            Path(current_app.config["DB_PATH"])
        )
        service = GuardrailService(
            repo, g.access_checker, g.audit
        )
        try:
            service.set_state(g.principal, guardrail_id, state)
        except AccessDeniedError:
            return _json_error("Nicht erlaubt", 403)
        except GuardrailNotFoundError:
            return _json_error("Nicht gefunden", 404)
        except GuardrailOperationError:
            return _json_error("Interner Fehler", 500)

        resp = jsonify({"ok": True})
        resp.headers["Cache-Control"] = "no-store"
        return resp


__all__ = ["register_guardrails_routes"]