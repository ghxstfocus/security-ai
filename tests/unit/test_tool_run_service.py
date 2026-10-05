# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer ToolRunService (Punkt 58 Schritt 1b)."""
from __future__ import annotations

import unittest
from typing import Any

from core.services.tool_run_service import (
    ToolRunAuditError,
    ToolRunOperationError,
    ToolRunRateLimitError,
    ToolRunService,
    ToolRunServiceError,
)
from harness.audit.writer import AuditWriteError
from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool, ToolArgumentValueError, ToolError


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


class _FakeRateLimiter:
    def __init__(self, ret: tuple[bool, int] = (True, 0)) -> None:
        self.ret = ret
        self.calls: list[str] = []
    def allow(self, key: str) -> tuple[bool, int]:
        self.calls.append(key)
        return self.ret

def _make_ping_tool(func: Any, level: Level = Level.READ) -> Tool:
    return Tool(
        name="ping",
        level=level,
        func=func,
        description="test",
        sandbox_profile="net_diag_local",
        allowed_args=frozenset({"target"}),
    )

class ToolRunServiceTests(unittest.TestCase):
    def _build(
        self,
        func: Any,
        allow: bool = True,
        ret: tuple[bool, int] = (True, 0),
        level: Level = Level.READ,
    ) -> tuple[ToolRunService, _FakeAudit, _FakeRegistry]:
        tool = _make_ping_tool(func, level=level)
        reg = _FakeRegistry({"ping": tool})
        audit = _FakeAudit()
        checker = _FakeChecker(allow=allow)
        limiter = _FakeRateLimiter(ret=ret)
        return (
            ToolRunService(reg, audit, checker, limiter),
            audit,
            reg,
        )

    def test_run_unknown_tool(self) -> None:
        svc, _, _ = self._build(lambda **kw: {})
        with self.assertRaises(ToolRunServiceError):
            svc.run("admin", "gibtsnicht", {})

    def test_run_tool_not_registered(self) -> None:
        reg = _FakeRegistry({})
        svc = ToolRunService(
            reg, _FakeAudit(), _FakeChecker(), _FakeRateLimiter()
        )
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

    def test_rate_limit_exceeded(self) -> None:
        svc, _, _ = self._build(
            lambda target: {"ok": True},
            ret=(False, 30),
        )
        with self.assertRaises(ToolRunRateLimitError):
            svc.run("admin", "ping", {"target": "127.0.0.1"})

    def test_rate_limit_error_has_retry_after_seconds(self) -> None:
        svc, _, _ = self._build(
            lambda target: {"ok": True},
            ret=(False, 30),
        )
        try:
            svc.run("admin", "ping", {"target": "127.0.0.1"})
        except ToolRunRateLimitError as e:
            self.assertEqual(e.retry_after_seconds, 30)
            self.assertGreater(e.retry_after_seconds, 0)
        else:
            self.fail("ToolRunRateLimitError erwartet")

    def test_rate_limit_backend_error_is_operation_error(self) -> None:
        svc, _, _ = self._build(
            lambda target: {"ok": True},
            ret=(False, 0),
        )
        with self.assertRaises(ToolRunOperationError):
            svc.run("admin", "ping", {"target": "127.0.0.1"})

    def test_level_2_rejected(self) -> None:
        svc, _, _ = self._build(
            lambda target: {"ok": True},
            level=Level.REVIEW_REQUIRED,
        )
        with self.assertRaises(ToolRunServiceError):
            svc.run("admin", "ping", {"target": "127.0.0.1"})

    def test_level_2_rejected_before_validate_args(self) -> None:
        svc, _, _ = self._build(
            lambda target: {"ok": True},
            level=Level.REVIEW_REQUIRED,
        )
        with self.assertRaises(ToolRunServiceError):
            svc.run("admin", "ping", {"unbekannt": "x"})

    def test_audit_error_raises_tool_run_audit_error(self) -> None:
        class _BadAudit:
            def log(self, **kw: Any) -> None:
                raise AuditWriteError("kaputt")
        tool = _make_ping_tool(lambda target: {"ok": True})
        reg = _FakeRegistry({"ping": tool})
        svc = ToolRunService(
            reg, _BadAudit(), _FakeChecker(), _FakeRateLimiter()
        )
        with self.assertRaises(ToolRunAuditError) as ctx:
            svc.run("admin", "ping", {"target": "127.0.0.1"})
        self.assertIsInstance(ctx.exception.__cause__, AuditWriteError)

    def test_original_args_used_in_audit(self) -> None:
        svc, audit, _ = self._build(
            lambda target: {"ok": True},
        )
        svc.run(
            "admin", "ping",
            {"target": "1.1.1.1"},
            original_args={"target": "1.1.1.1", "evil": "x"},
        )
        self.assertEqual(len(audit.entries), 1)
        # Der Service uebergibt original_args an audit.log(),
        # nicht das gefilterte args.
        self.assertEqual(
            audit.entries[0]["args"],
            {"target": "1.1.1.1", "evil": "x"},
        )

    def test_original_args_none_uses_args(self) -> None:
        svc, audit, _ = self._build(
            lambda target: {"ok": True},
        )
        svc.run("admin", "ping", {"target": "1.1.1.1"})
        self.assertEqual(len(audit.entries), 1)
        # Ohne original_args uebergibt der Service args.
        self.assertEqual(
            audit.entries[0]["args"],
            {"target": "1.1.1.1"},
        )

    def test_tool_argument_value_error_maps_to_400(self) -> None:
        def _boom(target):
            raise ToolArgumentValueError("kaputte Eingabe")
        svc, audit, _ = self._build(_boom)
        with self.assertRaises(ToolRunServiceError):
            svc.run("admin", "ping", {"target": "1.1.1.1"})
        self.assertEqual(len(audit.entries), 1)
        self.assertEqual(audit.entries[0]["execution_status"], "ERR")

    def test_tool_error_maps_to_500(self) -> None:
        def _boom(target):
            raise ToolError("betriebsfehler")
        svc, audit, _ = self._build(_boom)
        with self.assertRaises(ToolRunOperationError):
            svc.run("admin", "ping", {"target": "1.1.1.1"})
        self.assertEqual(len(audit.entries), 1)
        self.assertEqual(audit.entries[0]["execution_status"], "ERR")
