# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Dashboard-Routen fuer die Werkbank (Punkt 58, Auflage 1991).

- GET  /tools          device.read  (Seite)
- POST /api/tools/run  device.read  (JSON)

Die eigentliche Tool-Permission (tool.net_diag,
tool.sys_status, tool.db_read) prueft der ToolRunService
(Defense in Depth, DESIGN_DECISIONS Paragraph 11).

Ablauf POST /api/tools/run:
  1. CSRF-Header (X-CSRF-Token).
  2. Content-Type application/json.
  3. JSON-Body: {"tool": str, "args": dict}.
  4. Werkbank-Registry aus app.extensions.
  5. Key-Whitelist: args auf allowed_args filtern.
  6. RateLimitService (pro Request).
  7. ToolRunService.run(actor, tool_name,
                        args=filtered, original_args=roh).

Fehler-Mapping:
  ToolRunRateLimitError  -> 429 + Retry-After + no-store.
  ToolRunServiceError    -> 400 + no-store.
  ToolRunOperationError  -> 500 + no-store.
  ToolArgumentError      -> 400 + no-store.
"""
from __future__ import annotations

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
from core.services.rate_limit_service import RateLimitService
from core.services.tool_run_service import (
    ToolRunOperationError,
    ToolRunRateLimitError,
    ToolRunService,
    ToolRunServiceError,
)
from harness.tool_registry.tool import ToolArgumentError


def _json_error(message: str, status: int) -> Response:
    resp = jsonify({"ok": False, "error": message})
    resp.status_code = status
    resp.headers["Cache-Control"] = "no-store"
    return resp


def register_tools_routes(app: Flask) -> None:

    @app.route("/tools", methods=["GET"])
    @require_permission("device.read")
    def tools_page() -> str:
        return render_template(
            "tools.html",
            page_title="Werkzeuge",
        )

    @app.route("/api/tools/run", methods=["POST"])
    @require_permission("device.read")
    def tools_run() -> Response:
        # 1. CSRF
        submitted = request.headers.get("X-CSRF-Token")
        expected = session.get("_csrf_token")
        if not csrf.validate(submitted, expected):
            return _json_error("Ungueltige Anfrage", 400)

        # 2. Content-Type
        if not request.is_json:
            return _json_error("Ungueltige Anfrage", 400)

        # 3. Body
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return _json_error("Ungueltige Anfrage", 400)
        tool_name = payload.get("tool")
        if not isinstance(tool_name, str) or not tool_name:
            return _json_error("Ungueltige Anfrage", 400)
        args = payload.get("args")
        if not isinstance(args, dict):
            return _json_error("Ungueltige Anfrage", 400)

        # 4. Registry
        registry = current_app.extensions.get(
            "workbench_registry"
        )
        if registry is None:
            return _json_error("Interner Fehler", 500)
        if not registry.has(tool_name):
            return _json_error("Unbekanntes Tool", 400)

        # 5. Key-Whitelist (Auflage 1980)
        tool = registry.get(tool_name)
        allowed_args = tool.allowed_args
        filtered_args = {
            k: v for k, v in args.items() if k in allowed_args
        }

        # 6. RateLimiter (pro Request)
        rate_limiter = RateLimitService(
            g.conn,
            window_seconds=current_app.config[
                "WORKBENCH_RATE_WINDOW"
            ],
            max_requests=current_app.config[
                "WORKBENCH_RATE_MAX"
            ],
        )

        # 7. Service
        service = ToolRunService(
            registry=registry,
            audit=g.audit,
            checker=g.access_checker,
            rate_limiter=rate_limiter,
        )

        actor = g.principal
        try:
            result = service.run(
                actor=actor,
                tool_name=tool_name,
                args=filtered_args,
                original_args=args,
            )
        except ToolRunRateLimitError as exc:
            resp = jsonify(
                {"ok": False, "error": "Rate limit exceeded"}
            )
            resp.status_code = 429
            resp.headers["Retry-After"] = str(
                exc.retry_after_seconds
            )
            resp.headers["Cache-Control"] = "no-store"
            return resp
        except ToolRunServiceError:
            return _json_error("Ungueltige Anfrage", 400)
        except ToolArgumentError:
            return _json_error("Ungueltige Argumente", 400)
        except ToolRunOperationError:
            return _json_error("Interner Fehler", 500)

        resp = jsonify(
            {
                "ok": True,
                "output": result.get("output"),
                "tool": tool_name,
                "error": None,
            }
        )
        resp.headers["Cache-Control"] = "no-store"
        return resp


__all__ = ["register_tools_routes"]
