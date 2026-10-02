# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Regel: unknown_device_persistent.

Ergaenzung zu unknown_device (Punkt 73). Alarmiert, wenn
ein Geraet im Hauptnetz laenger als alarm_after_seconds
unbekannt ist (identifier nicht in der Whitelist) und
beim ersten Auftreten bereits first_seen in der DB hat.

Datenquelle: RuleContext.snapshot["first_seen"] (Map
identifier -> datetime). Der Orchestrator uebergibt den
Snapshot aus _load_inventory_snapshot.

Erstes Auftreten (first_seen == now, d.h. das Geraet wurde
im aktuellen Lauf angelegt): kein Output. Der sofortige
unknown_device-Alarm deckt diesen Fall ab.

Cooldown pro identifier, damit der Alarm nicht bei jedem
device_presence-Event erneut feuert.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from core.detection.rule_base import Rule, RuleContext
from core.events.event import Event, EventType, Severity

_TRIGGER_TYPES = frozenset({
    EventType.DEVICE_PRESENCE.value,
})

_DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "severity": "WARNING",
    "alarm_network": "Hauptnetz",
    "alarm_after_seconds": 3600,
    "alert_cooldown_seconds": 3600,
}


def _cfg(config: dict[str, Any], key: str) -> Any:
    if key in config:
        return config[key]
    return _DEFAULTS[key]


class UnknownDevicePersistentRule(Rule):
    id = "unknown_device_persistent"
    event_types = _TRIGGER_TYPES
    severity = Severity.WARNING
    description = (
        "Alarmiert, wenn ein unbekanntes Geraet im Hauptnetz "
        "laenger als alarm_after_seconds unbekannt ist."
    )

    def evaluate(self, event: Event, context: RuleContext) -> list[Event]:
        if event.event_type not in self.event_types:
            return []

        cfg = context.config or {}
        if not _cfg(cfg, "enabled"):
            return []

        if event.data.get("network_type") != _cfg(cfg, "alarm_network"):
            return []

        if event.data.get("known") is not False:
            return []

        identifier = event.data.get("identifier")
        if not identifier:
            return []

        snapshot = context.snapshot
        if not isinstance(snapshot, dict):
            return []
        first_seen_map = snapshot.get("first_seen")
        if not isinstance(first_seen_map, dict):
            return []
        first_seen = first_seen_map.get(identifier)
        if not isinstance(first_seen, datetime):
            return []

        now = context.now
        try:
            delta = (now - first_seen).total_seconds()
        except TypeError:
            return []

        threshold = _cfg(cfg, "alarm_after_seconds")
        if delta < threshold:
            return []

        # Cooldown pro identifier.
        state = context.state
        cd_key = f"persist_last:{identifier}"
        cooldown = _cfg(cfg, "alert_cooldown_seconds")
        last = state.get(cd_key)
        if last:
            try:
                last_delta = (now - last[-1]).total_seconds()
            except TypeError:
                last_delta = cooldown + 1
            if 0 <= last_delta < cooldown:
                return []
        state.record(cd_key, now)

        severity_name = _cfg(cfg, "severity")
        try:
            severity = Severity(severity_name)
        except ValueError:
            severity = Severity.WARNING

        from core.events.event import Event as _Event
        from core.events.event import new_event_id
        return [
            _Event(
                event_id=new_event_id(),
                timestamp=event.timestamp,
                source=f"detection:{self.id}",
                event_type=EventType.UNKNOWN_DEVICE_PERSISTENT.value,
                severity=severity,
                data={
                    "identifier": identifier,
                    "entity_name": event.data.get("entity_name"),
                    "network_type": event.data.get("network_type"),
                    "known": False,
                    "first_seen": first_seen.isoformat(),
                    "unknown_seconds": int(delta),
                    "trigger_event_id": event.event_id,
                    "trigger_event_type": event.event_type,
                },
                network_id=event.network_id,
            )
        ]


__all__ = ["UnknownDevicePersistentRule"]
