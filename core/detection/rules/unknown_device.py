# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Regel: unknown_device.

Triggert auf device_presence / device_offline. Alarmiert nur, wenn
das Geraet im Hauptnetz unbekannt ist (data["known"] is False).

Gastnetz und bekannte Geraete: kein Output.
"""
from __future__ import annotations

from core.detection.rule_base import Rule, RuleContext
from core.events.event import Event, EventType, Severity
from core.sentinels import FALLBACK_SENTINEL

_DEFAULT_ALARM_NETWORK = "Hauptnetz"
_TRIGGER_TYPES = frozenset({
    EventType.DEVICE_PRESENCE.value,
    EventType.DEVICE_OFFLINE.value,
})


class UnknownDeviceRule(Rule):
    id = "unknown_device"
    event_types = _TRIGGER_TYPES
    severity = Severity.WARNING
    description = (
        "Alarmiert, wenn ein unbekanntes Geraet im Hauptnetz erscheint "
        "oder verschwindet."
    )

    def evaluate(self, event: Event, context: RuleContext) -> list[Event]:
        if event.event_type not in self.event_types:
            return []

        alarm_network = context.config.get(
            "alarm_network", _DEFAULT_ALARM_NETWORK
        )
        if event.data.get("network_type") != alarm_network:
            return []

        # Nur explizit unbekannt alarmiert. Fehlendes Feld != False.
        if event.data.get("known") is not False:
            return []

        # Fix C (Punkt 99): kein Alarm bei Sentinel-Name.
        # Defense in Depth (Fix B schliesst den Watcher-Pfad).
        if event.data.get("entity_name") == FALLBACK_SENTINEL:
            return []

        from core.events.event import Event as _Event
        from core.events.event import new_event_id
        return [
            _Event(
                event_id=new_event_id(),
                timestamp=event.timestamp,
                source=f"detection:{self.id}",
                event_type=EventType.UNKNOWN_DEVICE.value,
                severity=self.severity,
                data={
                    "identifier": event.data.get("identifier"),
                    "entity_name": event.data.get("entity_name"),
                    "network_type": event.data.get("network_type"),
                    "known": False,
                    "trigger_event_id": event.event_id,
                    "trigger_event_type": event.event_type,
                },
                network_id=event.network_id,
            )
        ]


__all__ = ["UnknownDeviceRule"]
