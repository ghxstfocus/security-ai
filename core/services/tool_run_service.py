# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ToolRunService (Punkt 58 Runde 1, Schritt 1b).

UI -> Service -> Tool-Registry -> Tool. Kein AgentLoop.
Nur Level 0-1 (read-only). Level 2+ kommt mit Change Request.

RBAC pro Tool-Gruppe (tool.net_diag, tool.sys_status, tool.db_read).
Fail closed: RBAC, Registry, Argumente, Audit.
"""
from __future__ import annotations

from typing import Any

from core.services.errors import OperationError, ServiceError
from harness.tool_registry.tool import ToolError


class ToolRunServiceError(ServiceError):
    """Fachlicher Fehler (4xx). Unbekanntes Tool, RBAC, Args."""

class ToolRunOperationError(OperationError):
    """Betriebsfehler (5xx). Tool-Ausfuehrung oder Audit."""

TOOL_PERMISSION: dict[str, str] = {
    "ping": "tool.net_diag",
    "traceroute": "tool.net_diag",
    "whois": "tool.net_diag",
    "dns_lookup": "tool.net_diag",
    "port_check": "tool.net_diag",
    "system_status": "tool.sys_status",
    "service_status": "tool.sys_status",
    "disk_usage": "tool.sys_status",
    "network_interfaces": "tool.sys_status",
    "audit_tail": "tool.db_read",
    "event_tail": "tool.db_read",
    "device_history": "tool.db_read",
    "scan_history": "tool.db_read",
}

class ToolRunService:
    def __init__(self, registry: Any, audit: Any, checker: Any) -> None:
        self._registry = registry
        self._audit = audit
        self._checker = checker

    def run(self, actor: str, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        permission = TOOL_PERMISSION.get(tool_name)
        if permission is None:
            raise ToolRunServiceError(f"Unbekanntes Tool: {tool_name!r}")
        if self._audit is None:
            raise ToolRunOperationError("audit_writer fehlt (fail closed)")
        self._checker.require_permission(actor, permission)
        if not self._registry.has(tool_name):
            raise ToolRunServiceError(f"Tool nicht registriert: {tool_name!r}")
        tool = self._registry.get(tool_name)
        try:
            tool.validate_args(args)
        except Exception as exc:
            self._log(actor, tool_name, permission, int(tool.level), "FORBIDDEN", "ERR", args, str(exc))
            raise ToolRunServiceError(f"Ungueltige Argumente fuer {tool_name!r}") from exc
        try:
            output = tool.func(**args)
        except ToolError as exc:
            self._log(actor, tool_name, permission, int(tool.level), "ALLOWED", "ERR", args, str(exc))
            raise ToolRunOperationError(f"Tool {tool_name!r} fehlgeschlagen") from exc
        except Exception as exc:
            self._log(actor, tool_name, permission, int(tool.level), "ALLOWED", "ERR", args, str(exc))
            raise ToolRunOperationError(f"Unerwarteter Fehler in {tool_name!r}") from exc
        self._log(actor, tool_name, permission, int(tool.level), "ALLOWED", "OK", args, None)
        return {"ok": True, "output": output, "tool": tool_name}

    def _log(self, actor: str, tool_name: str, permission: str, level: int, policy: str, status: str, args: dict[str, Any], error: str | None) -> None:
        details = {
            "kind": "tool_call",
            "source": "ui",
            "tool": tool_name,
            "permission": permission,
            "actor": actor,
        }
        self._audit.log(
            agent="security_ai",
            tool="tool_run_service",
            policy_result=policy,
            permission_level=level,
            execution_status=status,
            args=args,
            details=details,
            error=error,
        )

__all__ = [
    "TOOL_PERMISSION",
    "ToolRunOperationError",
    "ToolRunService",
    "ToolRunServiceError",
]
