"""
Integrationstest: Event durch die DetectionEngine, beide Regeln geladen,
Configs aus detection/rules.yaml durchgereicht.
"""
from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from core.detection.engine import DetectionEngine
from core.events.event import (
    Event,
    EventType,
    Severity,
    new_event,
    new_event_id,
)

try:
    import yaml  # PyYAML
    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False


RULES_YAML = Path("detection/rules.yaml")


def _load_configs() -> dict:
    if not _HAVE_YAML or not RULES_YAML.exists():
        return {}
    with RULES_YAML.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


class EngineIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine()
        self.loaded = self.engine.load_rules_from_package(
            "core.detection.rules"
        )
        self.configs = _load_configs()

    def test_beide_regeln_geladen(self):
        self.assertIn("unknown_device", self.loaded)
        self.assertIn("port_scan", self.loaded)

    def test_unknown_device_ueber_engine(self):
        e = new_event(
            "fritzbox", EventType.DEVICE_PRESENCE.value, Severity.INFO,
            {
                "identifier": "192.168.178.87",
                "entity_name": "Ghxst-Server",
                "network_type": "Hauptnetz",
                "known": False,
            },
        )
        reports = self.engine.process(e, configs=self.configs)
        unknown = [r for r in reports if r.rule_id == "unknown_device"][0]
        self.assertEqual(len(unknown.alerts), 1)
        self.assertEqual(
            unknown.alerts[0].event_type, EventType.UNKNOWN_DEVICE.value
        )

    def test_port_scan_ueber_engine(self):
        base = datetime.now(UTC)
        alerts = []
        for i in range(12):
            ts = base + timedelta(seconds=i)
            e = Event(
                event_id=new_event_id(),
                timestamp=ts,
                source="sensor",
                event_type=EventType.SYN_PACKET.value,
                severity=Severity.INFO,
                data={
                    "src_ip": "192.168.178.87",
                    "dst_ip": "192.168.178.1",
                    "dst_port": 2000 + i,
                    "protocol": "tcp",
                },
                network_id="homelab-default",
            )
            reports = self.engine.process(
                e, configs=self.configs, now=ts
            )
            for r in reports:
                alerts.extend(r.alerts)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_type, EventType.PORT_SCAN.value)
        self.assertEqual(alerts[0].data["kind"], "port_scan")

    def test_falsches_network_kein_alarm(self):
        e = new_event(
            "fritzbox", EventType.DEVICE_PRESENCE.value, Severity.INFO,
            {
                "identifier": "192.168.179.5",
                "entity_name": "Gast-Phone",
                "network_type": "Gastnetz",
                "known": False,
            },
        )
        reports = self.engine.process(e, configs=self.configs)
        unknown = [r for r in reports if r.rule_id == "unknown_device"][0]
        self.assertEqual(unknown.alerts, [])


class ListRulesApiTests(unittest.TestCase):
    """Punkt 36: DetectionEngine.list_rules als oeffentliche API."""

    def setUp(self):
        self.engine = DetectionEngine()
        if not _HAVE_YAML:
            self.skipTest("PyYAML fehlt")
        self.configs = _load_configs()
        self.engine.load_rules_from_package(
            "core.detection.rules"
        )

    def test_list_rules_returns_rule_objects(self):
        rules = self.engine.list_rules()
        self.assertIsInstance(rules, list)
        self.assertGreater(len(rules), 0)
        for r in rules:
            self.assertTrue(hasattr(r, "id"))

    def test_list_rules_contains_unknown_device(self):
        ids = {r.id for r in self.engine.list_rules()}
        self.assertIn("unknown_device", ids)


if __name__ == "__main__":
    unittest.main()
