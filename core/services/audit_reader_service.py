# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

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
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from core.access.checker import AccessChecker
from core.inventory.repository import DeviceRepository
from core.reporting.audit_reader import (
    read_risk_assessments,
    read_risk_assessments_full,
)
from core.risk.models import CATEGORY_LABELS
from core.services import OperationError, ServiceError
from core.services.alert_explain import explain_alert
from core.services.search_service import (
    QUERY_MAX,
    QUERY_MIN,
    QUERY_RE,
)
from harness.audit.writer import AuditWriter

AUDIT_ID_RE = re.compile(r"^AUD-\d{4}-\d{2}-\d{2}-[0-9a-f]{8}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Punkt 80: Filter- und Pagination-Konstanten.
SINCE_HOURS_VALUES = (24, 168, 720)
NETWORK_TYPE_VALUES = ("Hauptnetz", "Gastnetz", "Extern")
IDENTIFIER_RE = re.compile(r"^[0-9A-Fa-f:]{1,32}$")
RESULT_LIMIT_HARD = 10000
PER_PAGE_DEFAULT = 20

# T4 (Auflage 1707): Kinds, die Aenderungen am Zustand
# bezeichnen. Filter fuer "Logs mit Aenderungen".
RECENT_CHANGE_KINDS = frozenset({
    "change_created",
    "change_approved",
    "change_rejected",
    "change_deployed",
    "change_rolled_back",
    "change_cancelled",
    "approval_requested",
    "approval_granted",
    "approval_rejected",
    "approval_expired",
})


class AuditReaderServiceError(ServiceError):
    """Fachlicher Fehler im AuditReaderService (4xx)."""


class AuditReaderOperationError(OperationError):
    """Betriebsfehler im AuditReaderService (5xx)."""


class AuditReaderService:
    def __init__(
        self,
        audit_writer: AuditWriter,
        checker: AccessChecker,
        device_repo: DeviceRepository | None = None,
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
        self._devices = device_repo

    def _require(self, actor: str, code: str) -> None:
        self._checker.require_permission(actor, code)

    def _validate_date(self, date_str: str) -> str:
        if not isinstance(date_str, str) or not DATE_RE.match(date_str):
            raise AuditReaderServiceError(
                f"Datum muss YYYY-MM-DD sein: {date_str!r}"
            )
        try:
            date.fromisoformat(date_str)
        except ValueError as exc:
            raise AuditReaderServiceError(
                f"Datum ungueltig: {date_str!r}"
            ) from exc
        return date_str

    def _read_day_impl(self, date_str: str) -> list[dict[str, Any]]:
        when = datetime.combine(
            date.fromisoformat(date_str),
            time.min,
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
                date.fromisoformat(date_str)
            except ValueError:
                continue
            result.extend(self._read_day_impl(date_str))
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

    def _load_events_by_id(self) -> dict[str, dict]:
        """Liest data/events-YYYY-MM-DD.jsonl (heute + gestern),
        indexiert per event_id. Fail-soft: fehlende Datei -> kein
        Eintrag, kein Fehler.
        """
        import json
        from pathlib import Path as _Path

        base = _Path("data")
        today = datetime.now(UTC).date()
        yesterday = today - timedelta(days=1)
        index: dict[str, dict] = {}
        for d in (yesterday, today):
            path = base / f"events-{d.isoformat()}.jsonl"
            if not path.is_file():
                continue
            try:
                with path.open(encoding="utf-8") as fh:
                    for line in fh:
                        s = line.strip()
                        if not s:
                            continue
                        try:
                            obj = json.loads(s)
                        except (TypeError, ValueError):
                            continue
                        if isinstance(obj, dict) and obj.get("event_id"):
                            index[obj["event_id"]] = obj
            except OSError:
                continue
        return index

    def list_recent_assessments_with_context(
        self,
        actor: str,
        since_hours: int = 24,
        category: str | None = None,
        identifier: str | None = None,
        network_type: str | None = None,
        q: str | None = None,
        page: int = 1,
        per_page: int = PER_PAGE_DEFAULT,
        max_entries: int = RESULT_LIMIT_HARD,
    ) -> dict[str, Any]:
        """Alarme mit Kontext (Punkt 79, Punkt 80).

        Basis: read_risk_assessments_full (mit base,
        modifiers, reasons). Zusaetzlich pro Eintrag:
        identifier, entity_name, internal_name,
        network_type, event_ip, last_ip, display_ip,
        alert_text (Klartext aus alert_explain).

        Filter (Punkt 80):
        - since_hours: in SINCE_HOURS_VALUES.
        - category: in CATEGORY_LABELS.
        - identifier: MATCH IDENTIFIER_RE.
        - network_type: in NETWORK_TYPE_VALUES.
        - q: QUERY_MIN..QUERY_MAX, QUERY_RE.

        Pagination: page >= 1, per_page fix 20.
        Sortierung: (timestamp, audit_id) absteigend.
        Rueckgabe: dict mit items, total, page,
        pages, per_page.
        """
        self._require(actor, "alert.view")

        # Validierung (fail closed).
        if since_hours not in SINCE_HOURS_VALUES:
            raise AuditReaderServiceError(
                f"since_hours nicht erlaubt: {since_hours!r}"
            )
        if category is not None and category not in CATEGORY_LABELS:
            raise AuditReaderServiceError(
                f"category unbekannt: {category!r}"
            )
        if network_type is not None and network_type not in NETWORK_TYPE_VALUES:
            raise AuditReaderServiceError(
                f"network_type unbekannt: {network_type!r}"
            )
        if identifier is not None and (
            not isinstance(identifier, str)
            or not IDENTIFIER_RE.match(identifier)
        ):
            raise AuditReaderServiceError(
                "identifier hat ungueltiges Format"
            )
        if q is not None:
            if not isinstance(q, str):
                raise AuditReaderServiceError("q muss String sein")
            q = q.strip()
            if len(q) < QUERY_MIN:
                raise AuditReaderServiceError("q zu kurz")
            if len(q) > QUERY_MAX:
                raise AuditReaderServiceError("q zu lang")
            if not QUERY_RE.match(q):
                raise AuditReaderServiceError(
                    "q enthaelt ungueltige Zeichen"
                )
        if (not isinstance(page, int)
                or isinstance(page, bool)
                or page < 1):
            raise AuditReaderServiceError(
                f"page out of range: {page!r}"
            )
        if (not isinstance(per_page, int)
                or isinstance(per_page, bool)
                or not (1 <= per_page <= 200)):
            raise AuditReaderServiceError(
                f"per_page out of range: {per_page!r}"
            )
        if (not isinstance(max_entries, int)
                or isinstance(max_entries, bool)
                or not (1 <= max_entries <= RESULT_LIMIT_HARD)):
            raise AuditReaderServiceError(
                f"max_entries out of range: {max_entries!r}"
            )

        base_dir = self._audit.base_dir
        entries = read_risk_assessments_full(
            base_dir, since_hours=since_hours,
            max_entries=max_entries,
        )
        events = self._load_events_by_id()

        # Devices einmalig laden (Performance).
        devices_by_id: dict[str, Any] = {}
        if self._devices is not None:
            try:
                for d in self._devices.list_all():
                    devices_by_id[d.identifier] = d
            except Exception:  # noqa: BLE001 - fail-soft
                devices_by_id = {}

        out: list[dict[str, Any]] = []
        for e in entries:
            lookup_id = (
                e.get("trigger_event_id") or e.get("event_id")
            )
            ev = events.get(lookup_id or "")
            ev_data = ev.get("data", {}) if isinstance(ev, dict) else {}
            ident = (
                ev_data.get("identifier")
                if isinstance(ev_data, dict) else None
            )
            entity_name = (
                ev_data.get("entity_name")
                if isinstance(ev_data, dict) else None
            )
            ntype = (
                ev_data.get("network_type")
                if isinstance(ev_data, dict) else None
            )
            event_ip = (
                ev_data.get("ip") if isinstance(ev_data, dict) else None
            )

            internal_name = None
            last_ip = None
            if ident and ident in devices_by_id:
                dev = devices_by_id[ident]
                internal_name = dev.internal_name
                last_ip = dev.last_ip

            display_ip = event_ip or last_ip or "-"

            reasons = e.get("reasons") or []
            alert_text = explain_alert(e.get("rule_id"), reasons)

            # Filter (Punkt 80).
            if category is not None and e.get("category") != category:
                continue
            if identifier is not None and ident != identifier:
                continue
            if network_type is not None and ntype != network_type:
                continue
            if q is not None:
                ql = q.lower()
                hay = " ".join(str(x).lower() for x in [
                    ident or "", alert_text or "",
                    entity_name or "", internal_name or "",
                ])
                if ql not in hay:
                    continue

            out.append({
                "audit_id": e.get("audit_id"),
                "timestamp": e.get("timestamp"),
                "event_id": e.get("event_id"),
                "category": e.get("category"),
                "score": e.get("score"),
                "rule_id": e.get("rule_id"),
                "tool": e.get("tool"),
                "identifier": ident,
                "entity_name": entity_name,
                "internal_name": internal_name,
                "network_type": ntype,
                "event_ip": event_ip,
                "last_ip": last_ip,
                "display_ip": display_ip,
                "alert_text": alert_text,
                "reasons": reasons,
            })

        # Sortierung (Auflage 1963): (timestamp, audit_id) absteigend.
        out.sort(
            key=lambda x: (str(x.get("timestamp") or ""),
                           str(x.get("audit_id") or "")),
            reverse=True,
        )

        # Pagination.
        total = len(out)
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        start = (page - 1) * per_page
        end = start + per_page

        return {
            "items": out[start:end],
            "total": total,
            "page": page,
            "pages": pages,
            "per_page": per_page,
        }

    def list_recent_by_kinds(
        self,
        actor: str,
        kinds: set[str],
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Letzte Audit-Eintraege mit details.kind in kinds.

        T4 (Auflage 1707). RBAC: audit.read.
        Liest die heutigen und gestrigen JSONL-Zeilen,
        filtert nach details.kind, liefert die letzten
        limit Eintraege (neueste zuerst).

        Rueckgabe-Format pro Eintrag:
            {"audit_id": ..., "timestamp": ...,
             "kind": ..., "details": {...}}
        """
        self._require(actor, "audit.read")
        if (not isinstance(limit, int)
                or isinstance(limit, bool)
                or not (1 <= limit <= 100)):
            raise AuditReaderServiceError(
                "limit out of range (1..100)"
            )
        if not kinds:
            return []
        want = frozenset(kinds)
        now = datetime.now(UTC)
        today = now
        yesterday = now - timedelta(days=1)
        out: list[dict[str, Any]] = []
        for when in (yesterday, today):
            entries = self._audit.read_day(when)
            for e in entries:
                details = e.details or {}
                kind = details.get("kind")
                if kind in want:
                    ts = e.timestamp
                    out.append({
                        "audit_id": e.audit_id,
                        "timestamp": (
                            ts.isoformat()
                            if isinstance(ts, datetime)
                            else str(ts)
                        ),
                        "kind": kind,
                        "details": details,
                    })
        out.sort(key=lambda x: x.get("timestamp") or "",
                 reverse=True)
        return out[:limit]


__all__ = [
    "RECENT_CHANGE_KINDS",
    "AuditReaderOperationError",
    "AuditReaderService",
    "AuditReaderServiceError",
]
