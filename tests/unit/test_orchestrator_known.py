"""Tests fuer Punkt 73a: known-Anreicherung im Orchestrator."""
from __future__ import annotations

import unittest
from datetime import UTC, datetime
from unittest import mock

from apps.security_ai.orchestrator import SecurityAI
from core.events.event import Event, EventType, Severity, new_event_id


def _presence(identifier, network_type="Hauptnetz"):
    return Event(
        event_id=new_event_id(),
        timestamp=datetime.now(UTC),
        source="fritzbox",
        event_type=EventType.DEVICE_PRESENCE.value,
        severity=Severity.INFO,
        data={
            "identifier": identifier,
            "mac": identifier,
            "entity_name": "kamera",
            "network_type": network_type,
        },
        network_id="homelab-default",
    )


class KnownInjectionTests(unittest.TestCase):
    """known wird vor Inventory-Update und Detection gesetzt."""

    def _orchestrator(self):
        # Wir brauchen die SecurityAI-Instanz ohne DB-Migrationen
        # (skip_migrations) - der Snapshot wird gemockt.
        return SecurityAI(skip_migrations=True)

    def _run_with_snapshot(self, whitelist, event):
        orch = self._orchestrator()
        pre = {
            "devices": set(),
            "whitelist": set(whitelist),
            "first_seen": {},
        }
        captured = {}

        def fake_process(ev, configs=None, now=None):
            captured["event"] = ev
            return []

        with mock.patch.object(orch, "_load_inventory_snapshot",
                               return_value=pre), \
                mock.patch.object(orch, "_update_inventory",
                                  return_value=True), \
                mock.patch.object(orch._detection, "process",
                                  side_effect=fake_process), \
                mock.patch.object(orch._audit, "log",
                                  return_value=None):
            orch.process(event)
        return captured.get("event")

    def test_known_true_for_whitelisted(self):
        ev = self._run_with_snapshot(["aa:01"], _presence("aa:01"))
        self.assertIsNotNone(ev)
        self.assertTrue(ev.data.get("known"))

    def test_known_false_for_not_whitelisted(self):
        ev = self._run_with_snapshot(["bb:01"], _presence("aa:02"))
        self.assertIsNotNone(ev)
        self.assertFalse(ev.data.get("known"))

    def test_known_false_when_identifier_missing(self):
        e = Event(
            event_id=new_event_id(),
            timestamp=datetime.now(UTC),
            source="sensor",
            event_type=EventType.DEVICE_PRESENCE.value,
            severity=Severity.INFO,
            data={"network_type": "Hauptnetz"},
            network_id="homelab-default",
        )
        ev = self._run_with_snapshot(["aa:01"], e)
        self.assertIsNotNone(ev)
        self.assertFalse(ev.data.get("known"))

    def test_known_false_on_snapshot_fail(self):
        # Bei Snapshot-Fehler liefert _load_inventory_snapshot
        # leere Sets (fail-safe). known = False.
        orch = self._orchestrator()
        pre = {"devices": set(), "whitelist": set(), "first_seen": {}}
        captured = {}

        def fake_process(ev, configs=None, now=None):
            captured["event"] = ev
            return []

        with mock.patch.object(orch, "_load_inventory_snapshot",
                               return_value=pre), \
                mock.patch.object(orch, "_update_inventory",
                                  return_value=True), \
                mock.patch.object(orch._detection, "process",
                                  side_effect=fake_process), \
                mock.patch.object(orch._audit, "log",
                                  return_value=None):
            orch.process(_presence("aa:03"))
        ev = captured.get("event")
        self.assertIsNotNone(ev)
        self.assertFalse(ev.data.get("known"))


class UnknownDeviceFireAfterKnownFalseTests(unittest.TestCase):
    """Ende-zu-Ende: known=False -> UnknownDeviceRule liefert Output."""

    def test_unknown_device_rule_fires_after_known_false(self):
        from core.detection.rule_base import RuleContext, RuleState
        from core.detection.rules.unknown_device import UnknownDeviceRule

        rule = UnknownDeviceRule()
        e = _presence("aa:04")
        # known=False per with_data simulieren.
        from core.events.event import with_data
        e = with_data(e, {"known": False})
        ctx = RuleContext(
            now=e.timestamp,
            network_id="homelab-default",
            config={},
            state=RuleState(maxlen=100),
        )
        out = rule.evaluate(e, ctx)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].event_type,
                         EventType.UNKNOWN_DEVICE.value)


if __name__ == "__main__":
    unittest.main()
