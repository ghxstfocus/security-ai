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

from typing import Any, TypedDict

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
    ToolRunAuditError,
    ToolRunOperationError,
    ToolRunRateLimitError,
    ToolRunService,
    ToolRunServiceError,
)
from harness.tool_registry.registry import ToolNotFoundError
from harness.tool_registry.tool import ToolArgumentError

# Anzeigename pro Tool (deutsch, in Klammern Zweck).
TOOL_LABELS: dict[str, str] = {
    "ping": "Ping (Erreichbarkeit)",
    "traceroute": "Traceroute (Weg zum Ziel)",
    "whois": "Whois (Domain-/IP-Info)",
    "dns_lookup": "DNS-Abfrage",
    "port_check": "Port-Check (offen/zu)",
    "system_status": "System-Status",
    "service_status": "Dienst-Status",
    "disk_usage": "Speicherplatz",
    "network_interfaces": "Netzwerk-Interfaces",
    "audit_tail": "Audit-Log (letzte N)",
    "event_tail": "Ereignis-Log (letzte N)",
    "device_history": "Geraete-Historie",
    "scan_history": "Scan-Historie",
}

# Formularfelder pro Tool. Muessen zu tool.allowed_args passen
# (Test: test_tool_fields_match_allowed_args).
TOOL_FIELDS: dict[str, tuple[ToolField, ...]] = {
    "ping": (
        {"name": "target", "label": "Ziel (IP oder Hostname)",
         "type": "text", "required": True},
        {"name": "count", "label": "Anzahl Pakete (1-10)",
         "type": "number", "required": False},
    ),
    "traceroute": (
        {"name": "target", "label": "Ziel (IP oder Hostname)",
         "type": "text", "required": True},
        {"name": "max_hops", "label": "Max. Hops",
         "type": "number", "required": False},
    ),
    "whois": (
        {"name": "target", "label": "Ziel (IP oder Hostname)",
         "type": "text", "required": True},
    ),
    "dns_lookup": (
        {"name": "hostname", "label": "Hostname",
         "type": "text", "required": True},
    ),
    "port_check": (
        {"name": "target", "label": "Ziel (IP oder Hostname)",
         "type": "text", "required": True},
        {"name": "port", "label": "Port (1-65535)",
         "type": "number", "required": True},
        {"name": "timeout", "label": "Timeout (s)",
         "type": "number", "required": False},
    ),
    "system_status": (),
    "service_status": (
        {"name": "unit", "label": "Unit",
         "type": "text", "required": True},
    ),
    "disk_usage": (
        {"name": "mountpoint", "label": "Mountpoint",
         "type": "text", "required": False},
    ),
    "network_interfaces": (),
    "audit_tail": (
        {"name": "limit", "label": "Limit",
         "type": "number", "required": False},
    ),
    "event_tail": (
        {"name": "limit", "label": "Limit",
         "type": "number", "required": False},
    ),
    "device_history": (
        {"name": "identifier", "label": "Identifier (MAC/IP)",
         "type": "text", "required": True},
        {"name": "limit", "label": "Limit",
         "type": "number", "required": False},
    ),
    "scan_history": (
        {"name": "limit", "label": "Limit",
         "type": "number", "required": False},
    ),
}

class ToolField(TypedDict):
    name: str
    label: str
    type: str
    required: bool


class ToolGroup(TypedDict):
    label: str
    permission_flag: str
    tools: tuple[str, ...]


# Gruppen fuer die Seite. label = Anzeige, permission_flag =
# RBAC-Flag im Template, tools = Reihenfolge.
TOOL_GROUPS: dict[str, ToolGroup] = {
    "netzwerk": {
        "label": "Netzwerk-Diagnose",
        "permission_flag": "can_view_tool_net_diag",
        "tools": ("ping", "traceroute", "whois",
                  "dns_lookup", "port_check"),
    },
    "system": {
        "label": "System",
        "permission_flag": "can_view_tool_sys_status",
        "tools": ("system_status", "service_status",
                  "disk_usage", "network_interfaces"),
    },
    "datenbank": {
        "label": "Datenbank",
        "permission_flag": "can_view_tool_db_read",
        "tools": ("audit_tail", "event_tail",
                  "device_history", "scan_history"),
    },
}


def _build_tools_by_group(
    registry: Any,
) -> dict[str, dict[str, Any]]:
    """Baut die Datenstruktur fuer tools.html.

    Pro Gruppe: label, permission_flag, tools (Liste).
    Pro Tool: name, label, description, fields.
    """
    result: dict[str, dict[str, Any]] = {}
    for key, group in TOOL_GROUPS.items():
        tools_list: list[dict[str, Any]] = []
        for name in group["tools"]:
            tool_obj = None
            if registry is not None:
                try:
                    tool_obj = registry.get(name)
                except ToolNotFoundError:
                    tool_obj = None
            desc = (
                getattr(tool_obj, 'description', '')
                if tool_obj is not None else ''
            )
            tools_list.append({
                "name": name,
                "label": TOOL_LABELS.get(name, name),
                "description": desc,
                "fields": TOOL_FIELDS.get(name, ()),
            })
        result[key] = {
            "label": group["label"],
            "permission_flag": group["permission_flag"],
            "tools": tools_list,
        }
    return result


def _json_error(message: str, status: int) -> Response:
    resp = jsonify({"ok": False, "error": message})
    resp.status_code = status
    resp.headers["Cache-Control"] = "no-store"
    return resp


class _ToolArgCastError(Exception):
    """Typecast-Fehler in der Route (intern, wird zu 400)."""

    def __init__(self, field_name: str) -> None:
        super().__init__(field_name)
        self.field_name = field_name


def _cast_args(
    tool_name: str,
    args: dict[str, Any],
) -> dict[str, Any]:
    """Wandelt Formularwerte gemaess TOOL_FIELDS-Typ um.

    Formularwerte kommen als String aus tools.js.
    type="number" -> int, wenn nicht moeglich float.
    Bei Konvertierungsfehler: _ToolArgCastError.
    """
    schema = TOOL_FIELDS.get(tool_name, ())
    type_map: dict[str, str] = {
        f["name"]: f["type"] for f in schema
    }
    result: dict[str, Any] = {}
    for key, val in args.items():
        if type_map.get(key) == "number":
            try:
                result[key] = int(val)
                continue
            except (ValueError, TypeError):
                pass
            try:
                result[key] = float(val)
                continue
            except (ValueError, TypeError):
                raise _ToolArgCastError(key)
        result[key] = val
    return result


def register_tools_routes(app: Flask) -> None:

    @app.route("/tools", methods=["GET"])
    @require_permission("device.read")
    def tools_page() -> str:
        registry = current_app.extensions.get(
            "workbench_registry"
        )
        tools_by_group = _build_tools_by_group(registry)
        return render_template(
            "tools.html",
            page_title="Werkzeuge",
            tools_by_group=tools_by_group,
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

        # 5b. Typecast (Auflage 2009): Formularwerte
        # kommen als String, type="number" wird konvertiert.
        try:
            filtered_args = _cast_args(tool_name, filtered_args)
        except _ToolArgCastError as exc:
            return _json_error(
                f"Ungueltige Eingabe: {exc.field_name}", 400
            )

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
        except ToolRunAuditError:
            return _json_error(
                "Audit-Fehler, Aktion nicht ausgefuehrt", 500
            )
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
