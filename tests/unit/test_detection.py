# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer die Detection-Regeln unknown_device und port_scan."""
from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from core.detection.rule_base import RuleContext, RuleState
from core.detection.rules.device_flapping import DeviceFlappingRule
from core.detection.rules.mac_change import MacChangeRule
from core.detection.rules.network_change import NetworkChangeRule
from core.detection.rules.port_scan import PortScanRule
from core.detection.rules.unknown_device import UnknownDeviceRule
from core.detection.rules.unknown_device_persistent import (
    UnknownDevicePersistentRule,
)
from core.events.event import (
    Event,
    EventType,
    Severity,
    new_event,
    new_event_id,
)


def _ctx(now=None, config=None, state=None):
    return RuleContext(
        now=now or datetime.now(UTC),
        network_id="homelab-default",
        config=config or {},
        state=state or RuleState(maxlen=500),
    )


class UnknownDeviceTests(unittest.TestCase):
    def setUp(self):
        self.rule = UnknownDeviceRule()

    def _device_event(self, *, network_type, known):
        return new_event(
            "fritzbox", EventType.DEVICE_PRESENCE.value, Severity.INFO,
            {
                "identifier": "192.168.178.87",
                "entity_name": "Ghxst-Server",
                "network_type": network_type,
                "known": known,
            },
        )

    def test_hauptnetz_bekannt_kein_output(self):
        out = self.rule.evaluate(
            self._device_event(network_type="Hauptnetz", known=True), _ctx())
        self.assertEqual(out, [])

    def test_hauptnetz_unbekannt_output_unknown_device(self):
        out = self.rule.evaluate(
            self._device_event(network_type="Hauptnetz", known=False), _ctx())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].event_type, EventType.UNKNOWN_DEVICE.value)
        self.assertEqual(out[0].severity, Severity.WARNING)
        self.assertEqual(out[0].data["identifier"], "192.168.178.87")
        self.assertFalse(out[0].data["known"])

    def test_gastnetz_kein_output(self):
        out = self.rule.evaluate(
            self._device_event(network_type="Gastnetz", known=False), _ctx())
        self.assertEqual(out, [])

    def test_falscher_event_typ_skip(self):
        e = new_event("sensor", EventType.SYN_PACKET.value, Severity.INFO,
                      {"src_ip": "10.0.0.1", "dst_port": 22})
        self.assertFalse(self.rule.matches(e))
        self.assertEqual(self.rule.evaluate(e, _ctx()), [])


class PortScanTests(unittest.TestCase):
    def setUp(self):
        self.rule = PortScanRule()
        self.state = RuleState(maxlen=2000)
        self.base = datetime.now(UTC)

    def _syn(self, port, ts, *, src_ip="192.168.178.87",
             dst_ip="192.168.178.1"):
        return Event(
            event_id=new_event_id(),
            timestamp=ts,
            source="sensor",
            event_type=EventType.SYN_PACKET.value,
            severity=Severity.INFO,
            data={"src_ip": src_ip, "dst_ip": dst_ip,
                  "dst_port": port, "protocol": "tcp"},
            network_id="homelab-default",
        )

    def _run(self, ports, *, offset_s=0, step_s=1, config=None):
        out = []
        for i, p in enumerate(ports):
            ts = self.base + timedelta(seconds=offset_s + i * step_s)
            out.extend(self.rule.evaluate(
                self._syn(p, ts), _ctx(now=ts, config=config, state=self.state)))
        return out

    def test_unter_schwelle_kein_output(self):
        out = self._run([1000 + i for i in range(5)])
        self.assertEqual(out, [])

    def test_ueber_schwelle_output_port_scan(self):
        out = self._run([2000 + i for i in range(12)])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].event_type, EventType.PORT_SCAN.value)
        self.assertEqual(out[0].data["kind"], "port_scan")
        self.assertGreaterEqual(out[0].data["ports_seen"], 10)

    def test_cooldown_greift(self):
        first = self._run([3000 + i for i in range(12)])
        self.assertEqual(len(first), 1)
        second = self._run([4000 + i for i in range(12)], offset_s=20)
        self.assertEqual(second, [])

    def test_falscher_event_typ_skip(self):
        e = new_event("fritzbox", EventType.DEVICE_PRESENCE.value, Severity.INFO,
                      {"identifier": "x", "network_type": "Hauptnetz", "known": False})
        self.assertFalse(self.rule.matches(e))
        self.assertEqual(self.rule.evaluate(e, _ctx(state=self.state)), [])


class NetworkChangeTests(unittest.TestCase):
    """Tests fuer die network_change-Regel (Punkt 70, Alarm-Paket A1)."""

    def setUp(self):
        self.rule = NetworkChangeRule()
        self.state = RuleState(maxlen=200)
        self.base = datetime.now(UTC)

    def _presence(self, *, identifier, network_type, ts):
        return Event(
            event_id=new_event_id(),
            timestamp=ts,
            source="fritzbox",
            event_type=EventType.DEVICE_PRESENCE.value,
            severity=Severity.INFO,
            data={
                "identifier": identifier,
                "entity_name": "S25-von-A",
                "network_type": network_type,
            },
            network_id="homelab-default",
        )

    def test_erstes_auftreten_kein_output(self):
        out = self.rule.evaluate(
            self._presence(identifier="aa:01", network_type="Hauptnetz",
                           ts=self.base),
            _ctx(now=self.base, state=self.state),
        )
        self.assertEqual(out, [])
        self.assertEqual(self.state.get("net:aa:01"), ["Hauptnetz"])

    def test_gleicher_netztyp_kein_output(self):
        self.rule.evaluate(
            self._presence(identifier="aa:01", network_type="Hauptnetz",
                           ts=self.base),
            _ctx(now=self.base, state=self.state),
        )
        out = self.rule.evaluate(
            self._presence(identifier="aa:01", network_type="Hauptnetz",
                           ts=self.base + timedelta(seconds=10)),
            _ctx(now=self.base + timedelta(seconds=10), state=self.state),
        )
        self.assertEqual(out, [])

    def test_gastnetz_zu_hauptnetz_output(self):
        self.rule.evaluate(
            self._presence(identifier="aa:02", network_type="Gastnetz",
                           ts=self.base),
            _ctx(now=self.base, state=self.state),
        )
        out = self.rule.evaluate(
            self._presence(identifier="aa:02", network_type="Hauptnetz",
                           ts=self.base + timedelta(seconds=10)),
            _ctx(now=self.base + timedelta(seconds=10), state=self.state),
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].event_type, EventType.NETWORK_CHANGE.value)
        self.assertEqual(out[0].data["previous_network_type"], "Gastnetz")
        self.assertEqual(out[0].data["network_type"], "Hauptnetz")

    def test_hauptnetz_zu_gastnetz_kein_output(self):
        self.rule.evaluate(
            self._presence(identifier="aa:03", network_type="Hauptnetz",
                           ts=self.base),
            _ctx(now=self.base, state=self.state),
        )
        out = self.rule.evaluate(
            self._presence(identifier="aa:03", network_type="Gastnetz",
                           ts=self.base + timedelta(seconds=10)),
            _ctx(now=self.base + timedelta(seconds=10), state=self.state),
        )
        self.assertEqual(out, [])

    def test_cooldown_greift(self):
        self.rule.evaluate(
            self._presence(identifier="aa:04", network_type="Gastnetz",
                           ts=self.base),
            _ctx(now=self.base, state=self.state),
        )
        first = self.rule.evaluate(
            self._presence(identifier="aa:04", network_type="Hauptnetz",
                           ts=self.base + timedelta(seconds=10)),
            _ctx(now=self.base + timedelta(seconds=10), state=self.state),
        )
        self.assertEqual(len(first), 1)
        self.rule.evaluate(
            self._presence(identifier="aa:04", network_type="Gastnetz",
                           ts=self.base + timedelta(seconds=20)),
            _ctx(now=self.base + timedelta(seconds=20), state=self.state),
        )
        self.rule.evaluate(
            self._presence(identifier="aa:04", network_type="Gastnetz",
                           ts=self.base + timedelta(seconds=25)),
            _ctx(now=self.base + timedelta(seconds=25), state=self.state),
        )
        third = self.rule.evaluate(
            self._presence(identifier="aa:04", network_type="Hauptnetz",
                           ts=self.base + timedelta(seconds=30)),
            _ctx(now=self.base + timedelta(seconds=30), state=self.state),
        )
        self.assertEqual(third, [])

    def test_falscher_event_typ_skip(self):
        e = new_event("fritzbox", EventType.DEVICE_OFFLINE.value, Severity.INFO,
                      {"identifier": "aa:05", "network_type": "Hauptnetz"})
        self.assertFalse(self.rule.matches(e))
        self.assertEqual(self.rule.evaluate(e, _ctx(state=self.state)), [])


class MacChangeTests(unittest.TestCase):
    """Tests fuer die mac_change-Regel (Punkt 71, Alarm-Paket A2)."""

    def setUp(self):
        self.rule = MacChangeRule()
        self.state = RuleState(maxlen=200)
        self.base = datetime.now(UTC)

    def _presence(self, *, identifier, entity_name, ts,
                  network_type="Hauptnetz"):
        return Event(
            event_id=new_event_id(),
            timestamp=ts,
            source="fritzbox",
            event_type=EventType.DEVICE_PRESENCE.value,
            severity=Severity.INFO,
            data={
                "identifier": identifier,
                "mac": identifier,
                "entity_name": entity_name,
                "network_type": network_type,
            },
            network_id="homelab-default",
        )

    def test_erstes_auftreten_kein_output(self):
        out = self.rule.evaluate(
            self._presence(identifier="aa:01", entity_name="S25-von-A",
                           ts=self.base),
            _ctx(now=self.base, state=self.state),
        )
        self.assertEqual(out, [])

    def test_gleicher_entity_andere_mac_output(self):
        self.rule.evaluate(
            self._presence(identifier="aa:01", entity_name="S25-von-A",
                           ts=self.base),
            _ctx(now=self.base, state=self.state),
        )
        t2 = self.base + timedelta(seconds=10)
        out = self.rule.evaluate(
            self._presence(identifier="aa:02", entity_name="S25-von-A", ts=t2),
            _ctx(now=t2, state=self.state),
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].event_type, EventType.MAC_CHANGE.value)
        self.assertEqual(out[0].data["mac"], "aa:02")
        self.assertIn("aa:01", out[0].data["known_macs"])

    def test_gleicher_entity_gleiche_mac_kein_output(self):
        self.rule.evaluate(
            self._presence(identifier="aa:01", entity_name="S25-von-A",
                           ts=self.base),
            _ctx(now=self.base, state=self.state),
        )
        t2 = self.base + timedelta(seconds=10)
        out = self.rule.evaluate(
            self._presence(identifier="aa:01", entity_name="S25-von-A", ts=t2),
            _ctx(now=t2, state=self.state),
        )
        self.assertEqual(out, [])

    def test_entity_none_kein_output(self):
        out = self.rule.evaluate(
            self._presence(identifier="aa:01", entity_name=None,
                           ts=self.base),
            _ctx(now=self.base, state=self.state),
        )
        self.assertEqual(out, [])

    def test_entity_sentinel_kein_output(self):
        out = self.rule.evaluate(
            self._presence(identifier="aa:01", entity_name="__FALLBACK__",
                           ts=self.base),
            _ctx(now=self.base, state=self.state),
        )
        self.assertEqual(out, [])

    def test_cooldown_greift(self):
        self.rule.evaluate(
            self._presence(identifier="aa:01", entity_name="S25-von-A",
                           ts=self.base),
            _ctx(now=self.base, state=self.state),
        )
        t2 = self.base + timedelta(seconds=10)
        first = self.rule.evaluate(
            self._presence(identifier="aa:02", entity_name="S25-von-A", ts=t2),
            _ctx(now=t2, state=self.state),
        )
        self.assertEqual(len(first), 1)
        t3 = self.base + timedelta(seconds=20)
        second = self.rule.evaluate(
            self._presence(identifier="aa:03", entity_name="S25-von-A", ts=t3),
            _ctx(now=t3, state=self.state),
        )
        self.assertEqual(second, [])

    def test_falscher_event_typ_skip(self):
        e = new_event("fritzbox", EventType.DEVICE_OFFLINE.value, Severity.INFO,
                      {"identifier": "aa:05", "mac": "aa:05",
                       "entity_name": "S25-von-A"})
        self.assertFalse(self.rule.matches(e))
        self.assertEqual(self.rule.evaluate(e, _ctx(state=self.state)), [])


class DeviceFlappingTests(unittest.TestCase):
    """Tests fuer die device_flapping-Regel (Punkt 72, A3)."""

    def setUp(self):
        self.rule = DeviceFlappingRule()
        self.state = RuleState(maxlen=200)
        self.base = datetime.now(UTC)

    def _change(self, *, identifier, ts, event_type=None, reason="state_change"):
        if event_type is None:
            event_type = EventType.DEVICE_PRESENCE.value
        return Event(
            event_id=new_event_id(),
            timestamp=ts,
            source="fritzbox",
            event_type=event_type,
            severity=Severity.INFO,
            data={
                "identifier": identifier,
                "mac": identifier,
                "entity_name": "kamera",
                "network_type": "Hauptnetz",
                "reason": reason,
            },
            network_id="homelab-default",
        )

    def _run_changes(self, n, step_s=60, reason="state_change",
                     offset_s=0, event_type=None):
        out = []
        for i in range(n):
            ts = self.base + timedelta(seconds=offset_s + i * step_s)
            out.extend(self.rule.evaluate(
                self._change(identifier="aa:01", ts=ts,
                             reason=reason, event_type=event_type),
                _ctx(now=ts, state=self.state),
            ))
        return out

    def test_unter_schwelle_kein_output(self):
        out = self._run_changes(3)
        self.assertEqual(out, [])

    def test_ueber_schwelle_output(self):
        out = self._run_changes(7)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].event_type, EventType.DEVICE_FLAPPING.value)
        self.assertGreaterEqual(out[0].data["changes_in_window"], 6)

    def test_ausserhalb_fenster_kein_output(self):
        out = self._run_changes(7, step_s=1200)
        self.assertEqual(out, [])

    def test_re_presence_zaehlt_nicht(self):
        out = self._run_changes(7, reason="re_presence")
        self.assertEqual(out, [])

    def test_cooldown_greift(self):
        """Zweiter Flattern-Vorfall innerhalb des Cooldowns -> kein Event.

        Erster Alarm bei base+300s (6. Wechsel). Cooldown 900s.
        Zweiter Lauf mit offset_s=400: alle Wechsel liegen im
        Cooldown-Fenster [base+300s, base+1200s).
        """
        first = self._run_changes(7)
        self.assertEqual(len(first), 1)
        second = self._run_changes(7, offset_s=400)
        self.assertEqual(second, [])

    def test_erstes_auftreten_kein_output(self):
        out = self._run_changes(1, reason="first_seen")
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()


class UnknownDevicePersistentTests(unittest.TestCase):
    """Punkt 74: unknown_device_persistent."""

    def setUp(self):
        self.rule = UnknownDevicePersistentRule()
        self.state = RuleState(maxlen=200)
        self.base = datetime.now(UTC)

    def _ctx(self, now, snapshot=None):
        return RuleContext(
            now=now,
            network_id="homelab-default",
            config={},
            state=self.state,
            snapshot=snapshot,
        )

    def _presence(self, *, identifier="aa:01", network_type="Hauptnetz",
                  known=False, ts=None):
        return Event(
            event_id=new_event_id(),
            timestamp=ts or self.base,
            source="fritzbox",
            event_type=EventType.DEVICE_PRESENCE.value,
            severity=Severity.INFO,
            data={
                "identifier": identifier,
                "mac": identifier,
                "entity_name": "kamera",
                "network_type": network_type,
                "known": known,
            },
            network_id="homelab-default",
        )

    def test_known_kein_output(self):
        snap = {"first_seen": {"aa:01": self.base - timedelta(hours=2)}}
        out = self.rule.evaluate(
            self._presence(known=True), self._ctx(self.base, snap),
        )
        self.assertEqual(out, [])

    def test_unknown_unter_schwelle_kein_output(self):
        snap = {"first_seen": {"aa:01": self.base - timedelta(minutes=5)}}
        out = self.rule.evaluate(
            self._presence(), self._ctx(self.base, snap),
        )
        self.assertEqual(out, [])

    def test_unknown_ueber_schwelle_output(self):
        snap = {"first_seen": {"aa:01": self.base - timedelta(hours=2)}}
        out = self.rule.evaluate(
            self._presence(), self._ctx(self.base, snap),
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].event_type,
                         EventType.UNKNOWN_DEVICE_PERSISTENT.value)
        self.assertGreaterEqual(out[0].data["unknown_seconds"], 3600)

    def test_falsches_netz_kein_output(self):
        snap = {"first_seen": {"aa:01": self.base - timedelta(hours=2)}}
        out = self.rule.evaluate(
            self._presence(network_type="Gastnetz"),
            self._ctx(self.base, snap),
        )
        self.assertEqual(out, [])

    def test_ohne_snapshot_kein_output(self):
        out = self.rule.evaluate(
            self._presence(), self._ctx(self.base, None),
        )
        self.assertEqual(out, [])

    def test_cooldown_greift(self):
        snap = {"first_seen": {"aa:01": self.base - timedelta(hours=2)}}
        first = self.rule.evaluate(
            self._presence(), self._ctx(self.base, snap),
        )
        self.assertEqual(len(first), 1)
        second = self.rule.evaluate(
            self._presence(), self._ctx(self.base + timedelta(minutes=10), snap),
        )
        self.assertEqual(second, [])

    def test_falscher_event_typ_skip(self):
        e = new_event("fritzbox", EventType.DEVICE_OFFLINE.value, Severity.INFO,
                      {"identifier": "aa:01", "network_type": "Hauptnetz",
                       "known": False})
        self.assertFalse(self.rule.matches(e))


if __name__ == "__main__":
    unittest.main()
