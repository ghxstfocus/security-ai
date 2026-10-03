# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer ToolRunService (Punkt 58 Schritt 1b)."""
from __future__ import annotations

import unittest
from typing import Any

from core.services.tool_run_service import (
    ToolRunOperationError,
    ToolRunService,
    ToolRunServiceError,
)
from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool, ToolError


class _FakeChecker:
    def __init__(self, allow: bool = True) -> None:
        self.allow = allow
        self.calls: list[tuple[str, str]] = []
    def require_permission(self, actor: str, code: str) -> None:
        self.calls.append((actor, code))
        if not self.allow:
            raise RuntimeError("denied")

class _FakeAudit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []
    def log(self, **kw: Any) -> None:
        self.entries.append(kw)

class _FakeRegistry:
    def __init__(self, tools: dict[str, Tool]) -> None:
        self._tools = tools
    def has(self, name: str) -> bool:
        return name in self._tools
    def get(self, name: str) -> Tool:
        return self._tools[name]

def _make_ping_tool(func: Any) -> Tool:
    return Tool(
        name="ping",
        level=Level.READ,
        func=func,
        description="test",
        sandbox_profile="net_diag_local",
        allowed_args=frozenset({"target"}),
    )

class ToolRunServiceTests(unittest.TestCase):
    def _build(self, func: Any, allow: bool = True) -> tuple[ToolRunService, _FakeAudit, _FakeRegistry]:
        tool = _make_ping_tool(func)
        reg = _FakeRegistry({"ping": tool})
        audit = _FakeAudit()
        checker = _FakeChecker(allow=allow)
        return ToolRunService(reg, audit, checker), audit, reg

    def test_run_unknown_tool(self) -> None:
        svc, _, _ = self._build(lambda **kw: {})
        with self.assertRaises(ToolRunServiceError):
            svc.run("admin", "gibtsnicht", {})

    def test_run_tool_not_registered(self) -> None:
        reg = _FakeRegistry({})
        svc = ToolRunService(reg, _FakeAudit(), _FakeChecker())
        with self.assertRaises(ToolRunServiceError):
            svc.run("admin", "ping", {"target": "127.0.0.1"})

    def test_run_rbac_denied(self) -> None:
        svc, _, _ = self._build(lambda **kw: {}, allow=False)
        with self.assertRaises(RuntimeError):
            svc.run("viewer", "ping", {"target": "127.0.0.1"})

    def test_run_invalid_args(self) -> None:
        svc, audit, _ = self._build(lambda **kw: {})
        with self.assertRaises(ToolRunServiceError):
            svc.run("admin", "ping", {"unbekannt": "x"})
        self.assertEqual(len(audit.entries), 1)
        self.assertEqual(audit.entries[0]["details"]["kind"], "tool_call")
        self.assertEqual(audit.entries[0]["execution_status"], "ERR")

    def test_run_success_audit_called(self) -> None:
        svc, audit, _ = self._build(lambda target: {"ok": True})
        result = svc.run("admin", "ping", {"target": "127.0.0.1"})
        self.assertTrue(result["ok"])
        self.assertEqual(len(audit.entries), 1)
        self.assertEqual(audit.entries[0]["details"]["source"], "ui")
        self.assertEqual(audit.entries[0]["execution_status"], "OK")
        self.assertEqual(audit.entries[0]["permission_level"], 0)

    def test_run_tool_error_raises_operation_error(self) -> None:
        def _boom(target: str) -> dict:
            raise ToolError("kaputt")
        svc, audit, _ = self._build(_boom)
        with self.assertRaises(ToolRunOperationError):
            svc.run("admin", "ping", {"target": "127.0.0.1"})
        self.assertEqual(len(audit.entries), 1)
        self.assertEqual(audit.entries[0]["execution_status"], "ERR")
