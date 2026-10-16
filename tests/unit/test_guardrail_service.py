"""Tests fuer GuardrailService (Phase 5)."""

from __future__ import annotations

import sqlite3
import unittest

from core.access.checker import AccessDeniedError
from core.guardrails.models import Guardrail, GuardrailLevel, GuardrailState
from core.guardrails.repository import GuardrailNotFoundError
from core.services.guardrail_service import (
    GuardrailOperationError,
    GuardrailService,
)


class _FakeRepo:
    def __init__(self, fehler: Exception | None = None) -> None:
        self._fehler = fehler
        self._store: dict[str, Guardrail] = {
            "gr-1": Guardrail(
                id="gr-1",
                name="Test-Guardrail",
                level=GuardrailLevel.WARN,
                state=GuardrailState.ENABLED,
            ),
        }

    def set_state(self, id: str, state: str) -> None:
        if self._fehler is not None:
            raise self._fehler
        g = self._store[id]
        self._store[id] = Guardrail(
            id=g.id,
            name=g.name,
            level=g.level,
            state=GuardrailState(state),
        )

    def get(self, id: str) -> Guardrail:
        if self._fehler is not None:
            raise self._fehler
        return self._store[id]

    def list_all(self) -> list[Guardrail]:
        return list(self._store.values())


class _FakeChecker:
    def __init__(self, erlauben: bool = True) -> None:
        self._erlauben = erlauben

    def require_permission(self, principal: str, code: str) -> None:
        if not self._erlauben:
            raise AccessDeniedError(
                f"Zugriff verweigert: principal={principal!r} "
                f"permission={code!r}"
            )


class _FakeAudit:
    def __init__(self) -> None:
        self.aufrufe: list[dict] = []

    def log(
        self,
        *,
        agent,
        tool,
        policy_result,
        permission_level,
        execution_status,
        args=None,
        duration_ms=0,
        output_hash="sha256:empty",
        network_id="homelab-default",
        details=None,
        error=None,
    ):
        self.aufrufe.append(
            {
                "agent": agent,
                "tool": tool,
                "policy_result": policy_result,
                "permission_level": permission_level,
                "execution_status": execution_status,
                "details": details,
            }
        )


class GuardrailServiceTests(unittest.TestCase):
    def test_list_guardrails_rbac_verweigert(self) -> None:
        service = GuardrailService(
            _FakeRepo(), _FakeChecker(erlauben=False), _FakeAudit()
        )
        with self.assertRaises(AccessDeniedError):
            service.list_guardrails("viewer1")

    def test_set_state_rbac_verweigert(self) -> None:
        service = GuardrailService(
            _FakeRepo(), _FakeChecker(erlauben=False), _FakeAudit()
        )
        with self.assertRaises(AccessDeniedError):
            service.set_state("viewer1", "gr-1", "disabled")

    def test_set_state_audit_eintrag(self) -> None:
        audit = _FakeAudit()
        service = GuardrailService(_FakeRepo(), _FakeChecker(), audit)
        service.set_state("admin1", "gr-1", "disabled")
        self.assertEqual(len(audit.aufrufe), 1)
        details = audit.aufrufe[0]["details"]
        self.assertEqual(details["kind"], "guardrail_state_changed")
        self.assertEqual(details["from_state"], "enabled")
        self.assertEqual(details["to_state"], "disabled")

    def test_fail_closed_ohne_audit_writer(self) -> None:
        with self.assertRaises(GuardrailOperationError):
            GuardrailService(_FakeRepo(), _FakeChecker(), None)

    def test_set_state_gibt_guardrail_zurueck(self) -> None:
        service = GuardrailService(_FakeRepo(), _FakeChecker(), _FakeAudit())
        ergebnis = service.set_state("admin1", "gr-1", "disabled")
        self.assertIsInstance(ergebnis, Guardrail)
        self.assertEqual(ergebnis.state, GuardrailState.DISABLED)

    def test_set_state_repo_fehler_wird_operation_error(self) -> None:
        repo = _FakeRepo(fehler=sqlite3.OperationalError("db weg"))
        service = GuardrailService(repo, _FakeChecker(), _FakeAudit())
        with self.assertRaises(GuardrailOperationError):
            service.set_state("admin1", "gr-1", "disabled")

    def test_set_state_not_found_propagiert_ungewickelt(self) -> None:
        repo = _FakeRepo(fehler=GuardrailNotFoundError("gr-1"))
        service = GuardrailService(repo, _FakeChecker(), _FakeAudit())
        with self.assertRaises(GuardrailNotFoundError):
            service.set_state("admin1", "gr-1", "disabled")


if __name__ == "__main__":
    unittest.main()