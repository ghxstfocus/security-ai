"""
ApprovalQueue — Fassade ueber ApprovalRepository + Audit.

Rollen:
- SQLite (core.approval.repository) ist die Quelle der Wahrheit.
- AuditWriter dokumentiert jede Anfrage und jede Entscheidung.
- Telegram (spaeter) ist nur Kanal, nicht Zustand.

Audit-Kinds:
- approval_requested
- approval_granted
- approval_rejected
- approval_expired

Aufrufer (Orchestrator) reicht eine offene sqlite3.Connection und
einen AuditWriter herein. Konvention wie DeviceRepository.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from core.approval.models import ApprovalRequest, ApprovalStatus
from core.approval.repository import (
    ApprovalNotFoundError,
    ApprovalRepository,
    ApprovalRepositoryError,
    ApprovalStateError,
)
from harness.audit.writer import AuditWriter

AGENT = "security_ai"
TOOL = "approval_queue"


class ApprovalEnqueueError(RuntimeError):
    """
    Wird geworfen, wenn enqueue die DB nicht beschreiben konnte.
    Fail closed: kein Audit, kein stiller Fallback.
    """


class ApprovalQueue:
    """Duenne Fassade: Repository + Audit."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        audit_writer: AuditWriter,
    ) -> None:
        self._repo = ApprovalRepository(conn)
        self._audit = audit_writer

    # ------------------------------------------------------------------ #
    # Intern: Audit-Helfer
    # ------------------------------------------------------------------ #

    def _log(self, kind: str, details: dict[str, Any]) -> None:
        payload = {"kind": kind}
        payload.update(details)
        self._audit.log(
            agent=AGENT,
            tool=TOOL,
            policy_result="ALLOWED",
            permission_level=0,
            execution_status="OK",
            details=payload,
        )

    # ------------------------------------------------------------------ #
    # enqueue
    # ------------------------------------------------------------------ #

    def enqueue(
        self,
        *,
        tool_name: str,
        args: dict[str, Any] | list[Any],
        requested_by: str = AGENT,
        reason: str | None = None,
        risk_category: str | None = None,
        risk_score: float | None = None,
        event_id: str | None = None,
        expires_at: str | None = None,
    ) -> ApprovalRequest:
        try:
            req = self._repo.create(
                tool_name=tool_name,
                args=args,
                requested_by=requested_by,
                reason=reason,
                risk_category=risk_category,
                risk_score=risk_score,
                event_id=event_id,
                expires_at=expires_at,
            )
        except Exception as exc:
            # DB ist Quelle der Wahrheit. Ohne DB-Eintrag kein Audit,
            # kein stiller Fallback.
            raise ApprovalEnqueueError(
                f"enqueue fehlgeschlagen: {exc}"
            ) from exc

        # Audit ist Nachweis. Wenn das Audit scheitert, ist die
        # Request bereits in der DB; AuditWriteError propagiert.
        self._log("approval_requested", {
            "request_id": req.request_id,
            "tool": tool_name,
            "risk_category": risk_category,
            "risk_score": risk_score,
        })
        return req

    # ------------------------------------------------------------------ #
    # grant / reject
    # ------------------------------------------------------------------ #

    def grant(
        self,
        request_id: str,
        decided_by: str,
        reason: str | None = None,
    ) -> ApprovalRequest:
        req = self._repo.decide(
            request_id,
            ApprovalStatus.GRANTED,
            decided_by=decided_by,
            decision_reason=reason,
        )
        self._log("approval_granted", {
            "request_id": req.request_id,
            "decided_by": decided_by,
        })
        return req

    def reject(
        self,
        request_id: str,
        decided_by: str,
        reason: str | None = None,
    ) -> ApprovalRequest:
        req = self._repo.decide(
            request_id,
            ApprovalStatus.REJECTED,
            decided_by=decided_by,
            decision_reason=reason,
        )
        details: dict[str, Any] = {
            "request_id": req.request_id,
            "decided_by": decided_by,
        }
        if reason is not None:
            details["reason"] = reason
        self._log("approval_rejected", details)
        return req

    # ------------------------------------------------------------------ #
    # expire_overdue
    # ------------------------------------------------------------------ #

    def expire_overdue(self, now: str | None = None) -> int:
        """
        Setzt alle PENDING-Requests mit expires_at < now auf EXPIRED.
        Schreibt pro geaenderter Zeile ein approval_expired-Audit.
        Liefert die Anzahl der geaenderten Zeilen.
        """
        pending_before = {
            r.request_id for r in self._repo.list_pending()
            if r.expires_at is not None
        }
        n = self._repo.expire_overdue(now_iso=now)
        if n > 0:
            # Nur die tatsaechlich betroffenen IDs auditieren.
            after = {
                r.request_id: r for r in self._repo.list_all(
                    status=ApprovalStatus.EXPIRED
                )
            }
            for rid in pending_before:
                if rid in after and after[rid].decided_at is not None:
                    # Nur die, die gerade eben expired sind, nicht alte.
                    self._log("approval_expired", {"request_id": rid})
        return n

    # ------------------------------------------------------------------ #
    # Delegation
    # ------------------------------------------------------------------ #

    def pending(self) -> list[ApprovalRequest]:
        return self._repo.list_pending()

    def list_all(
        self,
        status: ApprovalStatus | None = None,
        limit: int | None = None,
    ) -> list[ApprovalRequest]:
        return self._repo.list_all(status=status, limit=limit)

    def get(self, request_id: str) -> ApprovalRequest:
        return self._repo.get(request_id)

    def count_by_status(self) -> dict[ApprovalStatus, int]:
        return self._repo.count_by_status()


__all__ = [
    "AGENT",
    "TOOL",
    "ApprovalEnqueueError",
    "ApprovalNotFoundError",
    "ApprovalQueue",
    "ApprovalRepositoryError",
    "ApprovalStateError",
]
