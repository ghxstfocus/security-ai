"""
AuditReaderService: Service-Schicht fuer Audit-Lesen.

Kapselt harness.audit.writer.AuditWriter.read_day().
Der Web-Layer (Dashboard-Routen) darf NICHT direkt
auf harness zugreifen (Regel N).

Design:
- Lesender Service. Kein Schreiben.
- RBAC: audit.read vor jedem Zugriff.
- Input-Validierung (Regex), sonst AuditReaderServiceError.
- Kein DB-Zugriff, nur Datei-Lesen.
- Konstruktor-None -> AuditReaderOperationError (5xx).
- IO-Fehler aus read_day/read_risk_assessments werden
  NICHT gefangen. Variante D, Auflage 502-506 analog.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone, UTC
from typing import Any

from core.access.checker import AccessChecker
from core.reporting.audit_reader import (
    read_risk_assessments,
)
from core.services import OperationError, ServiceError
from harness.audit.writer import AuditWriter

AUDIT_ID_RE = re.compile(r"^AUD-\d{4}-\d{2}-\d{2}-[0-9a-f]{8}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class AuditReaderServiceError(ServiceError):
    """Fachlicher Fehler im AuditReaderService (4xx)."""


class AuditReaderOperationError(OperationError):
    """Betriebsfehler im AuditReaderService (5xx)."""


class AuditReaderService:
    def __init__(
        self,
        audit_writer: AuditWriter,
        checker: AccessChecker,
    ) -> None:
        if audit_writer is None:
            raise AuditReaderOperationError(
                "audit_writer ist Pflicht (fail closed)"
            )
        if checker is None:
            raise AuditReaderOperationError(
                "checker ist Pflicht (fail closed)"
            )
        self._audit = audit_writer
        self._checker = checker

    def _require(self, actor: str, code: str) -> None:
        self._checker.require_permission(actor, code)

    def _validate_date(self, date_str: str) -> str:
        if not isinstance(date_str, str) or not DATE_RE.match(date_str):
            raise AuditReaderServiceError(
                f"Datum muss YYYY-MM-DD sein: {date_str!r}"
            )
        try:
            datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError as exc:
            raise AuditReaderServiceError(
                f"Datum ungueltig: {date_str!r}"
            ) from exc
        return date_str

    def _read_day_impl(self, date_str: str) -> list[dict[str, Any]]:
        when = datetime.strptime(date_str, "%Y-%m-%d").replace(
            tzinfo=UTC,
        )
        return [e.to_dict() for e in self._audit.read_day(when)]

    def read_day(
        self, actor: str, date_str: str,
    ) -> list[dict[str, Any]]:
        self._require(actor, "audit.read")
        self._validate_date(date_str)
        return self._read_day_impl(date_str)

    def read_all(self, actor: str) -> list[dict[str, Any]]:
        self._require(actor, "audit.read")
        result: list[dict[str, Any]] = []
        base = self._audit.base_dir
        if not base.exists():
            return []
        for path in base.glob("*.jsonl"):
            date_str = path.stem
            if not DATE_RE.match(date_str):
                continue
            try:
                datetime.strptime(date_str, "%Y-%m-%d")
            except ValueError:
                continue
            for e in self._read_day_impl(date_str):
                result.append(e)
        result.sort(
            key=lambda d: d.get("timestamp", ""),
            reverse=True,
        )
        return result

    def find_by_audit_id(
        self, actor: str, audit_id: str,
    ) -> dict[str, Any] | None:
        self._require(actor, "audit.read")
        if not isinstance(audit_id, str) or \
                not AUDIT_ID_RE.match(audit_id):
            raise AuditReaderServiceError(
                f"audit_id ungueltig: {audit_id!r}"
            )
        date_str = audit_id[4:14]
        for e in self._read_day_impl(date_str):
            if e.get("audit_id") == audit_id:
                return e
        return None

    def list_recent_assessments(
        self, actor: str, limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Liefert die letzten risk_assessment-Eintraege.

        Format der Rueckgabe: siehe
        core.reporting.audit_reader.read_risk_assessments.

        RBAC: alert.view (neu seit Migration 0007).
        Range: limit 1..1000, bool ausgeschlossen.
        since_hours: fest 24 (kein Request-Parameter).
        """
        self._require(actor, "alert.view")
        if (not isinstance(limit, int)
                or isinstance(limit, bool)
                or not (1 <= limit <= 1000)):
            raise AuditReaderServiceError(
                "limit out of range (1..1000)"
            )
        return read_risk_assessments(
            self._audit.base_dir,
            since_hours=24,
            max_entries=limit,
        )


__all__ = [
    "AuditReaderOperationError",
    "AuditReaderService",
    "AuditReaderServiceError",
]
