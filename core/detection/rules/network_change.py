"""
Regel: network_change.

Triggert auf device_presence. Erkennt, wenn ein Geraet
von einem Netz-Typ in einen anderen wechselt.

Konkret (Default-Konfiguration):
- Gastnetz -> Hauptnetz: Alarm (ein Gast-Geraet hat
  Zugriff auf das Hauptnetz).
- Hauptnetz -> Gastnetz: kein Alarm (bewusster Wechsel).

Die Richtung ist ueber alarm_when.to_hauptnetz und
alarm_when.to_gastnetz konfigurierbar.

Zustand: RuleContext.state (Ringpuffer pro identifier).
Cooldown: analog port_scan, pro identifier.
Erstes Auftreten: kein Output (kein Vorgaenger bekannt).
"""
from __future__ import annotations

from typing import Any

from core.detection.rule_base import Rule, RuleContext
from core.events.event import Event, EventType, Severity

_TRIGGER_TYPES = frozenset({
    EventType.DEVICE_PRESENCE.value,
})

_DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "severity": "WARNING",
    "alert_cooldown_seconds": 300,
    "alarm_when_to_hauptnetz": True,
    "alarm_when_to_gastnetz": False,
}


def _cfg(config: dict[str, Any], key: str) -> Any:
    if key in config:
        return config[key]
    return _DEFAULTS[key]


class NetworkChangeRule(Rule):
    id = "network_change"
    event_types = _TRIGGER_TYPES
    severity = Severity.WARNING
    description = (
        "Erkennt einen Netz-Wechsel eines Geraets (z.B. Gast- "
        "nach Hauptnetz) und emittiert ein NETWORK_CHANGE-Event."
    )

    def evaluate(self, event: Event, context: RuleContext) -> list[Event]:
        if event.event_type not in self.event_types:
            return []

        cfg = context.config or {}
        if not _cfg(cfg, "enabled"):
            return []

        identifier = event.data.get("identifier")
        current_net = event.data.get("network_type")
        if not identifier or not current_net:
            return []

        state = context.state
        key = f"net:{identifier}"
        last = state.get(key)

        if not last:
            state.record(key, current_net)
            return []

        previous_net = last[-1]
        if previous_net == current_net:
            return []

        # Cooldown pro identifier
        cooldown = _cfg(cfg, "alert_cooldown_seconds")
        last_key = f"net_last:{identifier}"
        last_alert = state.get(last_key)
        now = context.now
        if last_alert:
            try:
                delta = (now - last_alert[-1]).total_seconds()
            except TypeError:
                delta = cooldown + 1
            if 0 <= delta < cooldown:
                state.record(key, current_net)
                return []

        # Richtung
        going_to_haupt = current_net == "Hauptnetz"
        going_to_gast = current_net == "Gastnetz"
        if going_to_haupt and not _cfg(cfg, "alarm_when_to_hauptnetz"):
            state.record(key, current_net)
            return []
        if going_to_gast and not _cfg(cfg, "alarm_when_to_gastnetz"):
            state.record(key, current_net)
            return []

        state.record(key, current_net)
        state.record(last_key, now)

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
                event_type=EventType.NETWORK_CHANGE.value,
                severity=severity,
                data={
                    "identifier": identifier,
                    "entity_name": event.data.get("entity_name"),
                    "network_type": current_net,
                    "previous_network_type": previous_net,
                    "trigger_event_id": event.event_id,
                    "trigger_event_type": event.event_type,
                },
                network_id=event.network_id,
            )
        ]


__all__ = ["NetworkChangeRule"]
