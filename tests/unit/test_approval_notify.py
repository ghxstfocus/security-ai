"""
Tests fuer SecurityAI._notify_approval.

Isoliert (ohne process()-Kette, ohne Detection/Risk).
Alle Aufrufe von telegram_alert_run werden gemockt.

Verhalten:
- disabled -> kein Telegram-Aufruf, Audit approval_notify_skipped.
- status != APPROVAL_REQUIRED -> kein Aufruf, kein Audit.
- APPROVAL_REQUIRED ohne request_id -> kein Aufruf, kein Audit.
- APPROVAL_REQUIRED mit request_id -> Telegram-Aufruf
  (Severity WARNING), Audit approval_notify_sent.
- Telegram-Fehler -> Audit approval_notify_failed, NICHT
  propagiert (Telegram ist Kanal, DB ist Wahrheit).
"""
from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from apps.security_ai.orchestrator import SecurityAI
from core.events.event import Event, Severity
from harness.agent_loop.loop import LoopResult, StepResult


def _event() -> Event:
    return Event(
        event_id="evt-1",
        timestamp=datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC),
        source="test",
        event_type="device_presence",
        severity=Severity.WARNING,
        data={
            "risk_category": "SECURITY_ALERT",
            "risk_score": 0.85,
        },
    )


def _loop_result(status: str, request_id: str | None,
                 tool: str = "nmap_scan") -> LoopResult:
    now = datetime(2026, 4, 21, 12, 0, 1, tzinfo=UTC)
    steps = [
        StepResult(
            tool=tool,
            status=status,
            output={"approval_request_id": request_id},
            error=None,
            duration_ms=5,
        ),
    ]
    return LoopResult(
        event_id="evt-1",
        started_at=now,
        finished_at=now,
        status=status,
        steps=steps,
        approval_request_id=request_id,
    )


class NotifyApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.app = SecurityAI(
            db_path=self.tmp / "inv.db",
            migrations_dir="data/migrations",
            audit_base_dir=self.tmp / "audit-logs",
            app_config_path=self.tmp / "cfg.yaml",
        )
        self.audit_calls: list[dict] = []

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _audit(self, tool: str, details: dict,
               execution_status: str = "OK") -> None:
        self.audit_calls.append({
            "tool": tool,
            "details": details,
            "execution_status": execution_status,
        })

    def _kinds(self) -> list[str]:
        return [c["details"].get("kind") for c in self.audit_calls]

    # ------------------------------------------------------------------ #
    # 1
    # ------------------------------------------------------------------ #
    def test_disabled_kein_telegram_aufruf(self):
        lr = _loop_result("APPROVAL_REQUIRED", "APR-2026-00001")
        with mock.patch(
            "apps.security_ai.orchestrator.telegram_alert_run"
        ) as m:
            self.app._notify_approval(lr, _event(), self._audit)
        self.assertFalse(m.called)
        self.assertIn("approval_notify_skipped", self._kinds())

    # ------------------------------------------------------------------ #
    # 2
    # ------------------------------------------------------------------ #
    def test_status_ok_kein_telegram_aufruf(self):
        self.app._approval_notify_enabled = True
        lr = _loop_result("OK", None)
        with mock.patch(
            "apps.security_ai.orchestrator.telegram_alert_run"
        ) as m:
            self.app._notify_approval(lr, _event(), self._audit)
        self.assertFalse(m.called)
        self.assertEqual(self.audit_calls, [])

    # ------------------------------------------------------------------ #
    # 3
    # ------------------------------------------------------------------ #
    def test_approval_required_ohne_request_id_kein_aufruf(self):
        self.app._approval_notify_enabled = True
        lr = _loop_result("APPROVAL_REQUIRED", None)
        with mock.patch(
            "apps.security_ai.orchestrator.telegram_alert_run"
        ) as m:
            self.app._notify_approval(lr, _event(), self._audit)
        self.assertFalse(m.called)
        self.assertEqual(self.audit_calls, [])

    # ------------------------------------------------------------------ #
    # 4
    # ------------------------------------------------------------------ #
    def test_approval_required_mit_request_id_telegram_aufruf(self):
        self.app._approval_notify_enabled = True
        lr = _loop_result("APPROVAL_REQUIRED", "APR-2026-00002")
        with mock.patch(
            "apps.security_ai.orchestrator.telegram_alert_run"
        ) as m:
            self.app._notify_approval(lr, _event(), self._audit)
        self.assertEqual(m.call_count, 1)
        kwargs = m.call_args.kwargs
        self.assertEqual(kwargs["severity"], "WARNING")
        self.assertIn("nmap_scan", kwargs["title"])
        self.assertIn("/approve APR-2026-00002", kwargs["message"])
        self.assertIn("/reject APR-2026-00002", kwargs["message"])
        self.assertIn("SECURITY_ALERT", kwargs["message"])
        self.assertIn("0.85", kwargs["message"])
        self.assertIn("evt-1", kwargs["message"])

    # ------------------------------------------------------------------ #
    # 5
    # ------------------------------------------------------------------ #
    def test_telegram_fehler_wird_geloggt_nicht_propagiert(self):
        self.app._approval_notify_enabled = True
        lr = _loop_result("APPROVAL_REQUIRED", "APR-2026-00003")
        with mock.patch(
            "apps.security_ai.orchestrator.telegram_alert_run",
            side_effect=RuntimeError("telegram down"),
        ):
            # Kein raise erwartet
            self.app._notify_approval(lr, _event(), self._audit)
        kinds = self._kinds()
        self.assertIn("approval_notify_failed", kinds)
        failed = next(
            c for c in self.audit_calls
            if c["details"].get("kind") == "approval_notify_failed"
        )
        self.assertIn("telegram down", failed["details"]["error"])
        self.assertEqual(failed["execution_status"], "ERROR")

    # ------------------------------------------------------------------ #
    # 6
    # ------------------------------------------------------------------ #
    def test_audit_eintrag_bei_erfolg(self):
        self.app._approval_notify_enabled = True
        lr = _loop_result("APPROVAL_REQUIRED", "APR-2026-00004")
        with mock.patch(
            "apps.security_ai.orchestrator.telegram_alert_run"
        ):
            self.app._notify_approval(lr, _event(), self._audit)
        sent = [
            c for c in self.audit_calls
            if c["details"].get("kind") == "approval_notify_sent"
        ]
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["details"]["request_id"], "APR-2026-00004")
        self.assertEqual(sent[0]["details"]["channel"], "telegram")
        self.assertEqual(sent[0]["execution_status"], "OK")


if __name__ == "__main__":
    unittest.main()
