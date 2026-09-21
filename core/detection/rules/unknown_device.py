"""
Regel: unknown_device.

Triggert auf device_presence / device_offline. Alarmiert nur, wenn
das Geraet im Hauptnetz unbekannt ist (data["known"] is False).

Gastnetz und bekannte Geraete: kein Output.
"""
from __future__ import annotations

from core.detection.rule_base import Rule, RuleContext
from core.events.event import Event, EventType, Severity, new_event

_ALARM_NETWORK = "Hauptnetz"
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

        if event.data.get("network_type") != _ALARM_NETWORK:
            return []

        # Nur explizit unbekannt alarmiert. Fehlendes Feld != False.
        if event.data.get("known") is not False:
            return []

        return [
            new_event(
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
