"""
Regel: device_flapping.

Triggert auf device_presence / device_offline.
Erkennt, wenn ein Geraet in einem Zeitfenster
mehrfach zwischen online und offline wechselt.

Re-Presence-Events (reason="re_presence", Punkt 68)
und Erstauftreten (reason="first_seen") werden
ignoriert. Nur echte Zustandswechsel
(reason="state_change") zaehlen.

Zustand: RuleContext.state (Ringpuffer pro identifier
mit Zeitstempeln der letzten Zustandswechsel).
Cooldown: pro identifier.
"""
from __future__ import annotations

from typing import Any

from core.detection.rule_base import Rule, RuleContext
from core.events.event import Event, EventType, Severity

_TRIGGER_TYPES = frozenset({
    EventType.DEVICE_PRESENCE.value,
    EventType.DEVICE_OFFLINE.value,
})

_DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "severity": "WARNING",
    "alarm_window_seconds": 900,
    "alarm_max_changes": 6,
    "alert_cooldown_seconds": 900,
}


def _cfg(config: dict[str, Any], key: str) -> Any:
    if key in config:
        return config[key]
    return _DEFAULTS[key]


class DeviceFlappingRule(Rule):
    id = "device_flapping"
    event_types = _TRIGGER_TYPES
    severity = Severity.WARNING
    description = (
        "Erkennt ein Geraet, das in kurzer Zeit mehrfach "
        "zwischen online und offline wechselt."
    )

    def evaluate(self, event: Event, context: RuleContext) -> list[Event]:
        if event.event_type not in self.event_types:
            return []

        cfg = context.config or {}
        if not _cfg(cfg, "enabled"):
            return []

        # Nur echte Zustandswechsel zaehlen.
        if event.data.get("reason") != "state_change":
            return []

        identifier = event.data.get("identifier")
        if not identifier:
            return []

        state = context.state
        key = f"flap:{identifier}"
        now = event.timestamp
        state.record(key, now)

        window = _cfg(cfg, "alarm_window_seconds")
        threshold = _cfg(cfg, "alarm_max_changes")

        entries = state.get(key)
        recent = []
        for ts in entries:
            try:
                delta = (now - ts).total_seconds()
            except TypeError:
                continue
            if 0 <= delta <= window:
                recent.append(ts)

        if len(recent) < threshold:
            return []

        # Cooldown
        cooldown = _cfg(cfg, "alert_cooldown_seconds")
        last_key = f"flap_last:{identifier}"
        last = state.get(last_key)
        if last:
            try:
                delta = (context.now - last[-1]).total_seconds()
            except TypeError:
                delta = cooldown + 1
            if 0 <= delta < cooldown:
                return []

        state.record(last_key, context.now)

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
                event_type=EventType.DEVICE_FLAPPING.value,
                severity=severity,
                data={
                    "identifier": identifier,
                    "entity_name": event.data.get("entity_name"),
                    "network_type": event.data.get("network_type"),
                    "changes_in_window": len(recent),
                    "window_s": window,
                    "trigger_event_id": event.event_id,
                    "trigger_event_type": event.event_type,
                },
                network_id=event.network_id,
            )
        ]


__all__ = ["DeviceFlappingRule"]
