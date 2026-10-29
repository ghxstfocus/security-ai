# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Dashboard-Route: Polling-Endpoint /api/dashboard/state.

Kategorie 3 (Route, RBAC, JSON, Datei-IO via Service).

- GET /api/dashboard/state  (JSON)
  RBAC: pro Sektion unterschiedlich.
  - devices -> device.read
  - alerts  -> alert.view
  - changes -> change.view
  Fehlende Permission -> Sektion fehlt im JSON
  (kein leerer Platzhalter, fail closed pro Sektion).

- Cache-Control: no-store.
- Kein CSRF (GET, kein State-Change).
- Kein Rate-Limit (5s-Polling von eingeloggten
  Nutzern ist Normalnutzung).
- Kein Request-Parameter.

Rueckgabe-Struktur:
  {
    "devices": {"active": [...], "recent": [...],
                "hauptnetz": N, "gastnetz": M,
                "available": true|false},
    "alerts": [...],
    "changes": [...],
    "timestamp": "ISO-8601-UTC"
  }
Sektion fehlt = Actor hat keine Permission.
"""
from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

import psutil
from flask import Flask, Response, g, jsonify

from apps.dashboard.decorators import require_permission
from core.access.checker import AccessDeniedError
from core.changes.repository import ChangeRepository
from core.inventory.repository import DeviceRepository
from core.inventory.whitelist import WhitelistRepository
from core.services.audit_reader_service import (
    RECENT_CHANGE_KINDS,
    AuditReaderService,
)
from core.services.change_service import ChangeService
from core.services.fritzbox_state_service import FritzboxStateService
from core.services.inventory_service import InventoryService

logger = logging.getLogger(__name__)

_TIMELINE_LIMIT = 15
_TIMELINE_TS_MAX = 40
_TIMELINE_KIND_MAX = 100
_TIMELINE_ACTOR_MAX = 100
_TIMELINE_SUMMARY_MAX = 200


def _section_devices() -> dict | None:
    """Geraete-Sektion (device.read). Fehlt bei AccessDeniedError."""
    try:
        inv = InventoryService(
            device_repo=DeviceRepository(g.conn),
            whitelist_repo=WhitelistRepository(g.conn),
            checker=g.access_checker,
        )
        state = FritzboxStateService(g.access_checker).get_state(
            g.principal,
        )
        devices = inv.list_devices(g.principal)
        counts = inv.count_by_network(g.principal)
        hosts = state.get("hosts", {}) if state.get("available") else {}
        active_macs = [
            mac for mac, info in hosts.items()
            if isinstance(info, dict) and info.get("active") is True
        ]
        active_set = set(active_macs)
        active = [d for d in devices if d.get("identifier") in active_set]
        recent = devices[:5]
        return {
            "active": active,
            "recent": recent,
            "hauptnetz": counts.get("Hauptnetz", 0),
            "gastnetz": counts.get("Gastnetz", 0),
            "available": bool(state.get("available")),
        }
    except AccessDeniedError:
        return None


def _section_alerts() -> list | None:
    """Alarme-Sektion (alert.view). Fehlt bei AccessDeniedError.

    Liefert pro Eintrag zusaetzlich can_link=True, wenn
    der Actor auch audit.read hat (Titel-Link auf
    /audit/<audit_id>). Ohne diese Permission wird der
    Link nicht gesetzt (RBAC pro Link, Punkt 33).
    """
    try:
        svc = AuditReaderService(
            audit_writer=g.audit,
            checker=g.access_checker,
        )
        entries = svc.list_recent_assessments(
            g.principal, limit=5,
        )
    except AccessDeniedError:
        return None
    try:
        g.access_checker.require_permission(
            g.principal, "audit.read",
        )
        can_link = True
    except AccessDeniedError:
        can_link = False
    return [
        {**e, "can_link": can_link} for e in entries
    ]


def _section_changes() -> list | None:
    """Changes-Sektion (change.view). Fehlt bei AccessDeniedError."""
    try:
        svc = ChangeService(
            repo=ChangeRepository(g.conn),
            checker=g.access_checker,
            audit_writer=g.audit,
        )
        return svc.list_all(g.principal)[:5]
    except AccessDeniedError:
        return None


def _section_system() -> dict | None:
    """System-Sektion (device.read). Fehlt bei AccessDeniedError.

    T4 (Auflage 1708):
    - cpu_percent(interval=0.1) misst 100 ms.
    - virtual_memory().percent direkt.
    """
    try:
        g.access_checker.require_permission(
            g.principal, "device.read",
        )
        cpu = psutil.cpu_percent(interval=0.1)
        vm = psutil.virtual_memory()
        return {
            "cpu_percent": float(cpu),
            "ram_percent": float(vm.percent),
            "ram_used_gb": round(vm.used / (1024 ** 3), 1),
            "ram_total_gb": round(vm.total / (1024 ** 3), 1),
            "available": True,
        }
    except AccessDeniedError:
        return None


def _section_recent_changes() -> list | None:
    """Letzte Change-/Approval-Kinds (audit.read).

    T4 (Auflage 1708). Fehlt bei AccessDeniedError.
    """
    try:
        svc = AuditReaderService(
            audit_writer=g.audit,
            checker=g.access_checker,
        )
        return svc.list_recent_by_kinds(
            g.principal, set(RECENT_CHANGE_KINDS), limit=5,
        )
    except AccessDeniedError:
        return None


def _timeline_get(entry: object, key: str) -> object:
    """Mapping- oder getattr-Zugriff fuer Timeline-Eintraege."""
    if isinstance(entry, Mapping):
        return entry.get(key)
    return getattr(entry, key, None)


def _timeline_str(value: object, max_len: int) -> str:
    """None -> "", sonst str() und auf max_len kuerzen."""
    if value is None:
        return ""
    return str(value)[:max_len]


def _section_timeline(
    reader: object,
    principal: object,
    checker: object,
) -> list[dict]:
    """Timeline-Sektion (audit.read). Fail closed, nie None.

    - Ohne audit.read: [] (kein Leak, kein Crash).
    - read_events(limit=15), defensiv normalisiert.
    - Keine details/args_json/Freitext durchreichen.
    """
    try:
        allowed = checker.has_permission(principal, "audit.read")
    except (AttributeError, TypeError):
        return []
    if not allowed:
        return []
    try:
        raw = reader.read_events(limit=_TIMELINE_LIMIT)
    except (OSError, ValueError) as exc:
        logger.warning("timeline read_events failed: %s", type(exc).__name__)
        return []
    except Exception as exc:  # noqa: BLE001 - AuditReaderError etc.
        logger.warning("timeline read_events failed: %s", type(exc).__name__)
        return []
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return []
    result: list[dict] = []
    for entry in raw:
        if not isinstance(entry, Mapping) and not hasattr(entry, "__dict__"):
            continue
        details = _timeline_get(entry, "details")
        kind_raw = None
        if isinstance(details, Mapping):
            kind_raw = details.get("kind")
        if kind_raw is None:
            kind_raw = _timeline_get(entry, "kind")
        actor_raw = _timeline_get(entry, "actor")
        if actor_raw is None:
            actor_raw = _timeline_get(entry, "principal")
        if actor_raw is None:
            actor_raw = _timeline_get(entry, "tool")
        summary_raw = _timeline_get(entry, "action")
        if summary_raw is None:
            summary_raw = _timeline_get(entry, "tool_name")
        result.append({
            "ts": _timeline_str(
                _timeline_get(entry, "ts"), _TIMELINE_TS_MAX,
            ),
            "kind": _timeline_str(kind_raw, _TIMELINE_KIND_MAX),
            "actor": _timeline_str(actor_raw, _TIMELINE_ACTOR_MAX),
            "summary": _timeline_str(
                summary_raw, _TIMELINE_SUMMARY_MAX,
            ),
        })
        if len(result) >= _TIMELINE_LIMIT:
            break
    return result


def _section_timeline_entries(
    reader: object,
    principal: object,
    checker: object,
) -> dict:
    """Timeline-Sektion (audit.read). Fail closed, nie None.

    - Ohne audit.read: {"entries": []} (kein Leak, kein Crash).
    - read_events(limit=15), defensiv normalisiert.
    - Fehler von read_events: fail closed (leere Liste).
    """
    try:
        allowed = checker.has_permission(principal, "audit.read")
    except (AttributeError, TypeError):
        return {"entries": []}
    if not allowed:
        return {"entries": []}
    try:
        # AuditReaderService.list_recent_assessments(actor, limit=...)
        # statt des erfundenen reader.read_events(...).
        raw = reader.list_recent_assessments(
            principal, limit=_TIMELINE_LIMIT,
        )
    except (OSError, ValueError, AttributeError, TypeError) as exc:
        logger.warning(
            "timeline list_recent_assessments failed: %s", type(exc).__name__,
        )
        return {"entries": []}
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return {"entries": []}
    entries: list[dict] = []
    for event in raw:
        if not isinstance(event, Mapping):
            continue
        details = event.get("details") or {}
        if not isinstance(details, Mapping):
            details = {}
        # GOLD: kind/action direkt aus event lesen (list_recent_assessments
        # legt sie nicht unter "details" ab).
        _kind = event.get("kind") or event.get("event_kind") or ""
        _action = (
            event.get("action")
            or event.get("message")
            or event.get("summary")
            or ""
        )
        if not _kind and isinstance(details, Mapping):
            _kind = details.get("kind") or ""
        if not _action and isinstance(details, Mapping):
            _action = details.get("action") or ""
        # GOLD: read_risk_assessments liefert category/score/rule_id/tool.
        # Wir mappen auf die Timeline-Felder:
        #   timestamp -> timestamp
        #   category  -> kind  (SECURITY_ALERT / CONFIRMED)
        #   rule_id   -> agent (unknown_device / unknown_device_persistent)
        #   score     -> action ("score=0.7")
        #   tool      -> tool  (risk_engine)
        _category = str(event.get("category") or "")
        _rule = str(event.get("rule_id") or "")
        _score = event.get("score")
        _kind_display = _category or _kind
        _agent_display = _rule or str(event.get("agent") or "")
        _action_display = (
            f"score={_score}" if _score is not None else _action
        )
        entries.append({
            "timestamp": _timeline_str(
                event.get("timestamp"), _TIMELINE_TS_MAX,
            ),
            "agent": _timeline_str(_agent_display, _TIMELINE_ACTOR_MAX),
            "tool": _timeline_str(
                event.get("tool"), _TIMELINE_KIND_MAX,
            ),
            "kind": _timeline_str(_kind_display, _TIMELINE_KIND_MAX),
            "action": _timeline_str(_action_display, _TIMELINE_SUMMARY_MAX),
        })
        if len(entries) >= _TIMELINE_LIMIT:
            break
    return {"entries": entries}


def register_state_routes(app: Flask) -> None:

    @app.route("/api/dashboard/state", methods=["GET"])
    @require_permission("device.read")
    def dashboard_state() -> Response:
        devices = _section_devices()
        alerts = _section_alerts()
        changes = _section_changes()
        system = _section_system()
        recent_changes = _section_recent_changes()
        # GOLD: _section_timeline_entries braucht AuditReaderService
        # (mit list_recent_assessments), nicht AuditWriter.
        from core.services.audit_reader_service import AuditReaderService
        _timeline_reader = AuditReaderService(
            audit_writer=g.audit, checker=g.access_checker,
        )
        timeline = _section_timeline_entries(
            _timeline_reader, g.principal, g.access_checker,
        )
        body: dict = {
            "timestamp": datetime.now(UTC).isoformat(),
        }
        if devices is not None:
            body["devices"] = devices
        if alerts is not None:
            body["alerts"] = alerts
        if changes is not None:
            body["changes"] = changes
        if system is not None:
            body["system"] = system
        if recent_changes is not None:
            body["recent_changes"] = recent_changes
        body["timeline"] = timeline
        resp = jsonify(body)
        resp.headers["Cache-Control"] = "no-store"
        return resp


__all__ = ["register_state_routes"]
