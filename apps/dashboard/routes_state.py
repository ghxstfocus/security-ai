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

TIMELINE_LIMIT = 15
_TIMELINE_LIMIT = TIMELINE_LIMIT
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
    """None -> "", sonst str() und auf max_len kuerzen.

    M-487-Test
    """
    if value is None:
        return ""
    return str(value)[:max_len]


def _format_timeline_ts(value: object) -> str:
    """ISO-8601-Timestamp fuer die Timeline formatieren.

    - Nicht-String oder leer -> "-" (fail safe).
    - "Z"-Suffix wird zu "+00:00" (UTC aus dem Audit-Log).
    - Zeitzonenbehaftet -> nach UTC normalisiert.
    - Naiv -> unveraendert formatiert.
    - ValueError -> Rohwert auf 19 Zeichen gekuerzt.
    """
    if not isinstance(value, str) or not value:
        return "-"
    raw = value
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return value[:19]
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC)
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def _section_timeline(principal: object, checker: object) -> dict:
    """Timeline-Sektion (audit.read). Fail closed, wirft nie.

    - Ohne audit.read: {"available": False, "count": 0, "entries": []}.
    - read_events(limit=TIMELINE_LIMIT) aus core.audit_reader.
    - Last-Resort-Guard (noqa: BLE001): Audit-JSONL ist append-only und
      von aussen schreibbar; eine einzelne defekte Zeile darf den
      kompletten Dashboard-Poll nicht zerstoeren. Exception-Nachricht
      und Pfad werden nicht in den Response uebernommen.
    - Pro Event flaches dict: timestamp, actor, tool, kind, summary.
      Rohe details (args_json, decision_reason) werden nicht durchgereicht.
    - Reihenfolge bleibt wie von read_events geliefert.
    """
    empty = {"available": False, "count": 0, "entries": []}
    try:
        allowed = checker.has_permission(principal, "audit.read")
    except (AttributeError, TypeError):
        return empty
    if not allowed:
        return empty
    try:
        reader = AuditReaderService(
            audit_writer=g.audit,
            checker=g.access_checker,
        )
        raw = reader.list_recent_assessments(
            principal, limit=TIMELINE_LIMIT,
        )
    except Exception:  # noqa: BLE001 - Last-Resort-Guard, siehe Docstring
        logger.warning("timeline read_events failed")
        return empty
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return empty
    entries: list[dict] = []
    for event in raw:
        try:
            details = getattr(event, "details", None)
            kind = None
            if isinstance(details, Mapping):
                kind = details.get("kind")
            if kind is None:
                kind = getattr(event, "kind", None)
            actor = getattr(event, "agent", None)
            tool = getattr(event, "tool", None)
            action = getattr(event, "action", None)
            ts = getattr(event, "timestamp", None)
            kind_str = "—" if kind is None else str(kind)
            action_str = "" if action is None else str(action)
            summary = f"{kind_str} {action_str}".strip()
            if len(summary) > 120:
                summary = summary[:117] + "..."
            entries.append({
                "timestamp": "" if ts is None else str(ts),
                "actor": "—" if actor is None else str(actor),
                "tool": "—" if tool is None else str(tool),
                "kind": kind_str,
                "summary": summary,
            })
        except (AttributeError, TypeError, ValueError):
            continue
        if len(entries) >= TIMELINE_LIMIT:
            break
    return {
        "available": True,
        "count": len(entries),
        "entries": entries,
    }


def _section_timeline_entries(
    reader: object,
    principal: object,
    checker: object,
) -> list[dict]:
    """Timeline-Sektion (audit.read). Fail closed, nie None.

    - Ohne audit.read: [] (kein Leak, kein Crash).
    - read_events(limit=15), defensiv normalisiert.
    - Fehler von read_events: fail closed (leere Liste).
    - Pro Eintrag: ts, kind, agent, action, score, audit_id, href.
    - Eintraege ohne audit_id werden uebersprungen (kein toter Link).
    """
    try:
        allowed = checker.has_permission(principal, "audit.read")
    except (AttributeError, TypeError):
        return []
    if not allowed:
        return []
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
        return []
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return []
    entries: list[dict] = []
    for event in raw:
        if not isinstance(event, Mapping):
            continue
        audit_id = event.get("audit_id") or event.get("id")
        if not audit_id:
            continue
        kind = event.get("kind") or event.get("category") or ""
        agent = event.get("agent") or "security_ai"
        action = event.get("action") or event.get("rule_id") or ""
        score = event.get("score")
        entries.append({
            "ts": _format_timeline_ts(event.get("timestamp")),
            "kind": _timeline_str(kind, _TIMELINE_KIND_MAX),
            "agent": _timeline_str(agent, _TIMELINE_ACTOR_MAX),
            "action": _timeline_str(action, _TIMELINE_SUMMARY_MAX),
            "score": score,
            "audit_id": audit_id,
            "href": f"/audit/{audit_id}",
        })
        if len(entries) >= _TIMELINE_LIMIT:
            break
    entries = sorted(
        entries,
        key=lambda e: float(e["score"]) if isinstance(e.get("score"), (int, float)) else 0.0,
        reverse=True,
    )
    return entries


def register_state_routes(app: Flask) -> None:

    @app.route("/api/dashboard/state", methods=["GET"])
    @require_permission("device.read")
    def dashboard_state() -> Response:
        devices = _section_devices()
        alerts = _section_alerts()
        changes = _section_changes()
        system = _section_system()
        recent_changes = _section_recent_changes()
        timeline = _section_timeline(g.principal, g.access_checker)
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


__all__ = ["TIMELINE_LIMIT", "register_state_routes"]
