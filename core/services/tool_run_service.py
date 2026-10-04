# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ToolRunService (Punkt 58 Runde 1, Schritt 1b).

UI -> Service -> Werkbank-Registry -> Tool. Kein AgentLoop.
Nur Level 0-1 (read-only). Level 2+ kommt mit Change Request.

RBAC pro Tool-Gruppe (tool.net_diag, tool.sys_status, tool.db_read).
Fail closed: RBAC, Registry, Argumente, Audit.

Audit-Konvention (Auflage 1987):
  tool=<tool_name>, details.component="tool_run_service".
  Siehe DESIGN_DECISIONS Paragraph 2 (tool = Komponente).
"""
from __future__ import annotations

from typing import Any

from core.services.errors import OperationError, ServiceError
from harness.permissions.levels import Level
from harness.tool_registry.tool import ToolError


class ToolRunServiceError(ServiceError):
    """Fachlicher Fehler (4xx). Unbekanntes Tool, RBAC, Args."""

class ToolRunOperationError(OperationError):
    """Betriebsfehler (5xx). Tool-Ausfuehrung oder Audit."""


class ToolRunRateLimitError(ServiceError):
    """Rate-Limit erreicht (4xx). Route mappt auf 429."""

    def __init__(self, retry_after_seconds: int, message: str) -> None:
        super().__init__(message)
        self.retry_after_seconds = int(retry_after_seconds)

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
    def __init__(
        self,
        registry: Any,
        audit: Any,
        checker: Any,
        rate_limiter: Any,
    ) -> None:
        self._registry = registry
        self._audit = audit
        self._checker = checker
        self._rate_limiter = rate_limiter

    def run(
        self,
        actor: str,
        tool_name: str,
        args: dict[str, Any],
        *,
        original_args: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        permission = TOOL_PERMISSION.get(tool_name)
        if permission is None:
            raise ToolRunServiceError(f"Unbekanntes Tool: {tool_name!r}")
        if self._audit is None:
            raise ToolRunOperationError("audit_writer fehlt (fail closed)")
        self._checker.require_permission(actor, permission)
        # RateLimitService.allow() liefert (allowed, retry_after).
        # (False, 0) bedeutet interner DB-Fehler (fail closed,
        # kein Raise im Service). Vertrag dokumentiert in
        # core/services/rate_limit_service.py Zeilen 61-67.
        allowed, retry_after = self._rate_limiter.allow(
            f"{actor}:{tool_name}"
        )
        if not allowed:
            if retry_after > 0:
                raise ToolRunRateLimitError(
                    retry_after_seconds=retry_after,
                    message=f"Rate limit exceeded for tool {tool_name}",
                )
            raise ToolRunOperationError(
                f"Rate limit backend error for tool {tool_name}"
            )
        if not self._registry.has(tool_name):
            raise ToolRunServiceError(f"Tool nicht registriert: {tool_name!r}")
        tool = self._registry.get(tool_name)
        if tool.level > Level.READ:
            raise ToolRunServiceError(
                f"Tool {tool.name} hat Level {int(tool.level)}, "
                f"Werkbank erlaubt nur Level 0-1."
            )
        try:
            tool.validate_args(args)
        except Exception as exc:
            self._log(actor, tool_name, permission, int(tool.level), "FORBIDDEN", "ERR", args, str(exc), original_args)
            raise ToolRunServiceError(f"Ungueltige Argumente fuer {tool_name!r}") from exc
        try:
            output = tool.func(**args)
        except ToolError as exc:
            self._log(actor, tool_name, permission, int(tool.level), "ALLOWED", "ERR", args, str(exc), original_args)
            raise ToolRunOperationError(f"Tool {tool_name!r} fehlgeschlagen") from exc
        except Exception as exc:
            self._log(actor, tool_name, permission, int(tool.level), "ALLOWED", "ERR", args, str(exc), original_args)
            raise ToolRunOperationError(f"Unerwarteter Fehler in {tool_name!r}") from exc
        self._log(actor, tool_name, permission, int(tool.level), "ALLOWED", "OK", args, None, original_args)
        return {"ok": True, "output": output, "tool": tool_name}

    def _log(
        self,
        actor: str,
        tool_name: str,
        permission: str,
        level: int,
        policy: str,
        status: str,
        args: dict[str, Any],
        error: str | None,
        original_args: dict[str, Any] | None = None,
    ) -> None:
        details = {
            "kind": "tool_call",
            "source": "ui",
            "tool": tool_name,
            "component": "tool_run_service",
            "permission": permission,
            "actor": actor,
        }
        self._audit.log(
            agent="security_ai",
            tool=tool_name,
            policy_result=policy,
            permission_level=level,
            execution_status=status,
            # Wenn die Route unbekannte Keys gefiltert hat, dokumentiert
            # der Audit-Hash den ORIGINAL-Versuch (original_args), nicht
            # das Ergebnis. Nachweis-Luecke sonst: ein Angreifer koennte
            # x-beliebige Keys schicken, ohne dass eine Spur bleibt.
            args=(original_args if original_args is not None else args),
            details=details,
            error=error,
        )

__all__ = [
    "TOOL_PERMISSION",
    "ToolRunOperationError",
    "ToolRunRateLimitError",
    "ToolRunService",
    "ToolRunServiceError",
]
