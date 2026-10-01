"""Tests fuer die Detection-Regeln unknown_device und port_scan."""
from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from core.detection.rule_base import RuleContext, RuleState
from core.detection.rules.network_change import NetworkChangeRule
from core.detection.rules.port_scan import PortScanRule
from core.detection.rules.unknown_device import UnknownDeviceRule
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


if __name__ == "__main__":
    unittest.main()
