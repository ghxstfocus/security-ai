"""
ApprovalService: Service-Schicht fuer Approvals.

Kapselt ApprovalQueue (harness/approval/queue.py) hinter
RBAC. Der Web-Layer (apps/dashboard/routes_approvals.py)
darf NICHT direkt auf harness zugreifen (Regel N).

Design:
- Rein lesend + entscheiden.
- RBAC: approval.view fuer Lesen, approval.decide fuer
  Entscheidungen.
- Audit erfolgt in ApprovalQueue. Kein zweites Audit hier
  (Auflage 34, Doppel-Audit vermeiden).
- Input-Validierung: request_id-Regex, decision-Whitelist,
  reason-Laenge. Fail closed.
- Repo-Fehler (ApprovalNotFoundError, ApprovalStateError)
  werden NICHT gefangen. Variante D, Auflage 502-506.
- Kein direkter Import von ApprovalRepository. Nur Queue.
- args_preview: json.dumps(sort_keys=True, ensure_ascii=True),
  default=str, gekuerzt auf 4000 Zeichen (Auflage 45).
"""
from __future__ import annotations

import json
import re

from core.access.checker import AccessChecker
from core.approval.repository import (
    ApprovalNotFoundError,
)
from core.services import ServiceError
from harness.approval.queue import ApprovalQueue

REQUEST_ID_RE = re.compile(r"^APR-\d{4}-\d{5}$")
DECISION_GRANTED = "granted"
DECISION_REJECTED = "rejected"
VALID_DECISIONS = (DECISION_GRANTED, DECISION_REJECTED)
REASON_MAX_LEN = 500
ARGS_PREVIEW_MAX_LEN = 4000
ARGS_PREVIEW_SUFFIX = "... [gekuerzt]"


class ApprovalServiceError(ServiceError):
    """Fachlicher Fehler im ApprovalService."""


class ApprovalService:
    def __init__(
        self,
        queue: ApprovalQueue,
        checker: AccessChecker,
    ) -> None:
        if queue is None:
            raise ApprovalServiceError(
                "queue ist Pflicht (fail closed)"
            )
        if checker is None:
            raise ApprovalServiceError(
                "checker ist Pflicht (fail closed)"
            )
        self._queue = queue
        self._checker = checker

    def _require(self, actor: str, code: str) -> None:
        self._checker.require_permission(actor, code)

    def _validate_request_id(self, request_id: object) -> str:
        if not isinstance(request_id, str):
            raise ApprovalServiceError("request_id muss String sein")
        if not REQUEST_ID_RE.match(request_id):
            raise ApprovalServiceError("request_id ungueltig")
        return request_id

    def _entry_to_dict(self, req) -> dict:
        d = req.to_dict()
        raw_args = d.get("args")
        try:
            text = json.dumps(
                raw_args, sort_keys=True, ensure_ascii=True,
                default=str,
            )
        except (TypeError, ValueError):
            text = "[]"
        if len(text) > ARGS_PREVIEW_MAX_LEN:
            text = text[:ARGS_PREVIEW_MAX_LEN] + ARGS_PREVIEW_SUFFIX
        d["args_preview"] = text
        # Roh-args nicht ans Template weitergeben, um
        # versehentliches Roh-Dumpen zu verhindern.
        d.pop("args", None)
        return d

    def list_pending(self, actor: str) -> list[dict]:
        self._require(actor, "approval.view")
        return [self._entry_to_dict(r) for r in self._queue.pending()]

    def list_all(self, actor: str) -> list[dict]:
        self._require(actor, "approval.view")
        return [self._entry_to_dict(r) for r in self._queue.list_all()]

    def get(self, actor: str, request_id: str) -> dict | None:
        self._require(actor, "approval.view")
        rid = self._validate_request_id(request_id)
        try:
            req = self._queue.get(rid)
        except ApprovalNotFoundError:
            return None
        return self._entry_to_dict(req)

    def decide(
        self,
        actor: str,
        request_id: str,
        *,
        decision: str,
        reason: str | None = None,
    ) -> dict:
        self._require(actor, "approval.decide")
        rid = self._validate_request_id(request_id)
        if decision not in VALID_DECISIONS:
            raise ApprovalServiceError("decision ungueltig")
        if reason is not None:
            if not isinstance(reason, str):
                raise ApprovalServiceError("reason muss String sein")
            if len(reason) > REASON_MAX_LEN:
                raise ApprovalServiceError(
                    f"reason zu lang (max {REASON_MAX_LEN})"
                )
        # Auflage 503: Repo-Fehler (ApprovalNotFoundError,
        # ApprovalStateError) propagieren ungefiltert.
        # Sie sind Persistenz-Fehler, keine Format-Fehler.
        # Deshalb kein try/except hier.
        if decision == DECISION_GRANTED:
            req = self._queue.grant(
                rid, decided_by=actor, reason=reason,
            )
        else:
            req = self._queue.reject(
                rid, decided_by=actor, reason=reason,
            )
        return self._entry_to_dict(req)


__all__ = [
    "DECISION_GRANTED",
    "DECISION_REJECTED",
    "REASON_MAX_LEN",
    "REQUEST_ID_RE",
    "ApprovalService",
    "ApprovalServiceError",
]
