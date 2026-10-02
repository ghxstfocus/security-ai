# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Regel: mac_change.

Triggert auf device_presence. Erkennt, wenn unter
demselben entity_name (Fingerprint) innerhalb eines
Zeitfensters mehrere verschiedene MACs auftauchen.

Beispiel: iOS/Android-Geraete mit aktivierter
MAC-Randomisierung wechseln die MAC pro WLAN-
Assoziation, behalten aber den Hostnamen. Der
Watcher sieht sie als mehrere Geraete.

Diese Regel emittiert ein MAC_CHANGE-Event mit
beiden MACs, sobald eine zweite MAC fuer denselben
Namen im Zeitfenster auftaucht.

Fallback-Namen (Sentinel __FALLBACK__) und
fehlende Namen werden ignoriert (kein Fingerprint
moeglich).

Zustand: RuleContext.state (Ringpuffer pro entity_name).
Cooldown: pro entity_name (alarm_cooldown_seconds).
"""
from __future__ import annotations

from typing import Any

from core.detection.rule_base import Rule, RuleContext
from core.events.event import Event, EventType, Severity

_TRIGGER_TYPES = frozenset({
    EventType.DEVICE_PRESENCE.value,
})

_SENTINEL = "__FALLBACK__"

_DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "severity": "WARNING",
    "alarm_cooldown_seconds": 600,
    "alarm_window_seconds": 600,
}


def _cfg(config: dict[str, Any], key: str) -> Any:
    if key in config:
        return config[key]
    return _DEFAULTS[key]


def _normalize_name(name: str) -> str:
    return name.strip().casefold()


class MacChangeRule(Rule):
    id = "mac_change"
    event_types = _TRIGGER_TYPES
    severity = Severity.WARNING
    description = (
        "Erkennt MAC-Wechsel bei gleichem entity_name "
        "(MAC-Randomisierung oder Spoofing)."
    )

    def evaluate(self, event: Event, context: RuleContext) -> list[Event]:
        if event.event_type not in self.event_types:
            return []

        cfg = context.config or {}
        if not _cfg(cfg, "enabled"):
            return []

        name_raw = event.data.get("entity_name")
        mac = event.data.get("mac") or event.data.get("identifier")
        if not name_raw or not mac:
            return []
        if name_raw == _SENTINEL:
            return []

        name = _normalize_name(str(name_raw))
        if not name:
            return []

        state = context.state
        key = f"macs:{name}"
        now = event.timestamp

        entries = state.get(key)

        # Unbekannte MAC?
        known_macs: set[str] = set()
        window = _cfg(cfg, "alarm_window_seconds")
        for e in entries:
            ts = e.get("ts")
            if ts is None:
                continue
            try:
                delta = (now - ts).total_seconds()
            except TypeError:
                continue
            if 0 <= delta <= window:
                known_macs.add(e.get("mac"))

        # Neue MAC: erst pruefen, dann State erweitern.
        is_new = mac not in known_macs and known_macs != set()

        state.record(key, {"ts": now, "mac": mac})

        if not is_new:
            return []

        # Cooldown pro Name
        cooldown = _cfg(cfg, "alarm_cooldown_seconds")
        last_key = f"mac_last:{name}"
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
                event_type=EventType.MAC_CHANGE.value,
                severity=severity,
                data={
                    "identifier": event.data.get("identifier"),
                    "entity_name": name_raw,
                    "mac": mac,
                    "known_macs": sorted(known_macs),
                    "trigger_event_id": event.event_id,
                    "trigger_event_type": event.event_type,
                },
                network_id=event.network_id,
            )
        ]


__all__ = ["MacChangeRule"]
