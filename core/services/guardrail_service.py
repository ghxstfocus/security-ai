"""GuardrailService (Phase 5).

Service-Schicht fuer Guardrails. RBAC + Audit.

Lesende Operationen: RBAC ja, Audit nein.
Schreibende Operationen: RBAC ja, Audit ja.

Fehler-Trennung (U5-Praez-A3):
  - RBAC-Verweigerung -> AccessDeniedError (4xx).
  - Repo-/Datenfehler -> GuardrailOperationError (5xx).
"""

from __future__ import annotations

import sqlite3

from core.access.checker import AccessChecker
from core.guardrails.models import Guardrail
from core.guardrails.repository import GuardrailRepository
from harness.audit.writer import AuditWriter

AGENT = "guardrail_service"
TOOL = "guardrail"


class GuardrailOperationError(Exception):
    """Service-Fehler (5xx). Nicht fuer RBAC-Verweigerung."""


class GuardrailService:
    """Service fuer Guardrails."""

    def __init__(
        self,
        repo: GuardrailRepository,
        checker: AccessChecker,
        audit_writer: AuditWriter,
    ) -> None:
        if audit_writer is None:
            raise GuardrailOperationError("audit_writer ist Pflicht")
        self._repo = repo
        self._checker = checker
        self._audit = audit_writer

    def list_guardrails(self, principal: str) -> list[Guardrail]:
        """Alle Guardrails. RBAC ja, Audit nein."""
        self._checker.require_permission(principal, "guardrail.view")
        return self._repo.list_all()

    def set_state(
        self, principal: str, guardrail_id: str, state: str
    ) -> Guardrail:
        """Setzt den Zustand eines Guardrails. RBAC + Audit."""
        self._checker.require_permission(principal, "guardrail.manage")
        try:
            vor = self._repo.get(guardrail_id)
            self._repo.set_state(guardrail_id, state)
            nach = self._repo.get(guardrail_id)
        except sqlite3.Error as exc:
            raise GuardrailOperationError(
                f"Guardrail-Repo-Fehler: {exc}"
            ) from exc
        self._audit.log(
            agent=AGENT,
            tool=TOOL,
            policy_result="ALLOWED",
            permission_level=0,
            execution_status="OK",
            details={
                "kind": "guardrail_state_changed",
                "guardrail_id": nach.id,
                "from_state": vor.state.value,
                "to_state": nach.state.value,
                "level": nach.level.value,
            },
        )
        return nach


__all__ = [
    "AGENT",
    "TOOL",
    "GuardrailOperationError",
    "GuardrailService",
]