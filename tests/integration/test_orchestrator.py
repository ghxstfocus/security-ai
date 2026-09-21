"""Integrationstest: Event durch den ganzen Stack (Inventory -> Detection -> Risk)."""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from apps.security_ai.orchestrator import (
    ProcessingAuditError,
    SecurityAI,
)
from core.events.event import Event, EventType, Severity, new_event_id


RULES_YAML = Path("detection/rules.yaml")
RISK_RULES = Path("core/risk/rules.yaml")


def _event(
    event_type: str,
    *,
    data: dict | None = None,
    ts: datetime | None = None,
) -> Event:
    return Event(
        event_id=new_event_id(),
        timestamp=ts or datetime.now(timezone.utc),
        source="test",
        event_type=event_type,
        severity=Severity.INFO,
        data=data or {},
        network_id="homelab-default",
    )


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "inventory.db"
        self.ai = SecurityAI(
            db_path=self.db_path,
            migrations_dir="data/migrations",
            detection_config_path=RULES_YAML,
            risk_rules_path=RISK_RULES,
        )

    def tearDown(self):
        self.ai.close()
        self.tmp.cleanup()

    # ------------------------------------------------------------------ #
    # Inventory-Update
    # ------------------------------------------------------------------ #

    def test_device_presence_legt_geraet_an(self):
        e = _event(EventType.DEVICE_PRESENCE.value, data={
            "identifier": "192.168.178.87",
            "entity_name": "Ghxst-Server",
            "network_type": "Hauptnetz",
            "known": False,
        })
        result = self.ai.process(e)
        d = self.ai.devices.get("192.168.178.87")
        self.assertIsNotNone(d)
        self.assertEqual(d.entity_name, "Ghxst-Server")
        # Detection hat gefeuert
        self.assertTrue(result.has_alerts)
        self.assertEqual(len(result.assessments), 1)

    def test_device_presence_aktualisiert_last_seen(self):
        e1 = _event(EventType.DEVICE_PRESENCE.value, data={
            "identifier": "192.168.178.10", "network_type": "Hauptnetz",
        })
        self.ai.process(e1)
        first = self.ai.devices.get("192.168.178.10")
        later = datetime.now(timezone.utc) + timedelta(seconds=5)
        e2 = _event(EventType.DEVICE_PRESENCE.value, data={
            "identifier": "192.168.178.10", "network_type": "Hauptnetz",
        }, ts=later)
        self.ai.process(e2)
        second = self.ai.devices.get("192.168.178.10")
        self.assertEqual(first.first_seen, second.first_seen)
        self.assertGreaterEqual(second.last_seen, first.last_seen)

    def test_device_offline_schreibt_history(self):
        e1 = _event(EventType.DEVICE_PRESENCE.value, data={
            "identifier": "192.168.178.10", "network_type": "Hauptnetz",
        })
        self.ai.process(e1)
        e2 = _event(EventType.DEVICE_OFFLINE.value, data={
            "identifier": "192.168.178.10", "network_type": "Hauptnetz",
        })
        self.ai.process(e2)
        h = self.ai.devices.history("192.168.178.10")
        types = [x["event_type"] for x in h]
        self.assertIn("device_offline", types)

    # ------------------------------------------------------------------ #
    # Detection -> Risk
    # ------------------------------------------------------------------ #

    def test_unknown_device_hauptnetz_unbekannt_hoher_score(self):
        # 23:30 -> nachts greift
        ts = datetime(2026, 9, 21, 23, 30, tzinfo=timezone.utc)
        e = _event(EventType.DEVICE_PRESENCE.value, ts=ts, data={
            "identifier": "192.168.178.87",
            "entity_name": "Ghxst-Server",
            "network_type": "Hauptnetz",
            "known": False,
        })
        r = self.ai.process(e)
        # Ein Alert (unknown_device), ein Assessment
        self.assertEqual(len(r.alerts), 1)
        self.assertEqual(r.alerts[0].event_type, EventType.UNKNOWN_DEVICE.value)
        self.assertEqual(len(r.assessments), 1)
        # Inventory-Update laeuft VOR Risk -> Geraet ist schon drin,
        # not_in_inventory greift NICHT mehr.
        # base 0.5 + hauptnetz 0.2 + nachts 0.1 + first_seen 0.15 = 0.95
        # (not_in_inventory greift nicht, weil Inventory-Update vorher lief)
        self.assertAlmostEqual(r.assessments[0].score, 0.95, places=4)
        self.assertEqual(r.assessments[0].category.value, "CONFIRMED")

    def test_gastnetz_kein_alarm(self):
        e = _event(EventType.DEVICE_PRESENCE.value, data={
            "identifier": "192.168.179.5",
            "entity_name": "Gast-Phone",
            "network_type": "Gastnetz",
            "known": False,
        })
        r = self.ai.process(e)
        self.assertFalse(r.has_alerts)
        self.assertEqual(r.assessments, [])

    def test_whitelist_senkt_score(self):
        # Geraet in Inventory + auf Whitelist.
        ts = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)  # Montagmittag
        e1 = _event(EventType.DEVICE_PRESENCE.value, ts=ts, data={
            "identifier": "192.168.178.10",
            "entity_name": "Laptop",
            "network_type": "Hauptnetz",
            "known": True,
        })
        self.ai.process(e1)
        self.ai.whitelist.add("192.168.178.10", "Laptop", added_by="admin")

        base = datetime(2026, 9, 21, 12, 1, tzinfo=timezone.utc)
        alerts_total = []
        assessments_total = []
        for i in range(12):
            ts_i = base + timedelta(seconds=i)
            e = _event(EventType.SYN_PACKET.value, ts=ts_i, data={
                "src_ip": "192.168.178.10",
                "dst_ip": "192.168.178.1",
                "dst_port": 2000 + i,
                "protocol": "tcp",
            })
            r = self.ai.process(e)
            alerts_total.extend(r.alerts)
            assessments_total.extend(r.assessments)
        self.assertEqual(len(alerts_total), 1)
        self.assertEqual(len(assessments_total), 1)
        # base 0.4 + many_ports 0.3 + is_whitelisted -0.2 = 0.5
        # (hauptnetz greift nicht, weil syn_packet kein network_type traegt)
        self.assertAlmostEqual(assessments_total[0].score, 0.5, places=4)

    def test_first_seen_bonus_greift(self):
        ts = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)  # Montagmittag
        e = _event(EventType.DEVICE_PRESENCE.value, ts=ts, data={
            "identifier": "192.168.178.99",
            "entity_name": "Neues-Geraet",
            "network_type": "Hauptnetz",
            "known": False,
        })
        r = self.ai.process(e)
        self.assertEqual(len(r.alerts), 1)
        # first_seen sollte im Alert-Event gesetzt sein
        self.assertTrue(r.alerts[0].data.get("first_seen"))
        # base 0.5 + hauptnetz 0.2 + first_seen 0.15 = 0.85 (nachts/wochenende aus)
        self.assertAlmostEqual(r.assessments[0].score, 0.85, places=4)

    def test_second_seen_kein_bonus(self):
        ts = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        e1 = _event(EventType.DEVICE_PRESENCE.value, ts=ts, data={
            "identifier": "192.168.178.98",
            "network_type": "Hauptnetz",
            "known": False,
        })
        self.ai.process(e1)
        # zweites Mal: Geraet ist jetzt im Inventory -> first_seen=False
        e2 = _event(EventType.DEVICE_PRESENCE.value, ts=ts, data={
            "identifier": "192.168.178.98",
            "network_type": "Hauptnetz",
            "known": False,
        })
        r = self.ai.process(e2)
        self.assertEqual(len(r.alerts), 1)
        self.assertFalse(r.alerts[0].data.get("first_seen"))
        # base 0.5 + hauptnetz 0.2 = 0.7 (kein first_seen)
        self.assertAlmostEqual(r.assessments[0].score, 0.7, places=4)

    def test_port_scan_durch_den_stack(self):
        base = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        results = []
        for i in range(12):
            e = _event(EventType.SYN_PACKET.value,
                       ts=base + timedelta(seconds=i), data={
                "src_ip": "192.168.178.87",
                "dst_ip": "192.168.178.1",
                "dst_port": 2000 + i,
                "protocol": "tcp",
            })
            results.append(self.ai.process(e))
        all_alerts = [a for r in results for a in r.alerts]
        all_assessments = [a for r in results for a in r.assessments]
        self.assertEqual(len(all_alerts), 1)
        self.assertEqual(len(all_assessments), 1)
        self.assertEqual(all_alerts[0].event_type, EventType.PORT_SCAN.value)
        self.assertEqual(all_assessments[0].rule_id, "port_scan")

    def test_unbekannter_event_typ_bekommt_default_assessment(self):
        e = _event("service_started")
        r = self.ai.process(e)
        # Kein Alert, kein Assessment (weil keine Detection-Regel triggert)
        self.assertFalse(r.has_alerts)
        self.assertEqual(r.assessments, [])

    def test_process_many(self):
        events = [
            _event(EventType.DEVICE_PRESENCE.value, data={
                "identifier": f"10.0.0.{i}",
                "network_type": "Hauptnetz",
                "known": True,
            })
            for i in range(3)
        ]
        results = self.ai.process_many(events)
        self.assertEqual(len(results), 3)
        self.assertEqual(self.ai.devices.count(), 3)

    def test_leere_db_kein_crash(self):
        # Frischer Orchestrator, kein Inventory.
        e = _event(EventType.DEVICE_PRESENCE.value, data={
            "identifier": "192.168.178.87",
            "network_type": "Hauptnetz",
            "known": False,
        })
        r = self.ai.process(e)
        self.assertTrue(r.has_alerts)

class OrchestratorAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit_dir = Path(self.tmp.name) / "audit"
        self.db_path = Path(self.tmp.name) / "inventory.db"
        self.ai = SecurityAI(
            db_path=self.db_path,
            migrations_dir="data/migrations",
            detection_config_path=RULES_YAML,
            risk_rules_path=RISK_RULES,
            audit_base_dir=self.audit_dir,
        )

    def tearDown(self):
        self.ai.close()
        self.tmp.cleanup()

    def _read_audit(self):
        lines = []
        for f in sorted(self.audit_dir.glob("*.jsonl")):
            for line in f.read_text(encoding="utf-8").strip().split("\n"):
                if line:
                    lines.append(json.loads(line))
        return lines

    def test_unknown_device_drei_bis_vier_eintraege(self):
        ts = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        e = _event(EventType.DEVICE_PRESENCE.value, ts=ts, data={
            "identifier": "192.168.178.77",
            "entity_name": "Neuling",
            "network_type": "Hauptnetz",
            "known": False,
        })
        self.ai.process(e)
        entries = self._read_audit()
        kinds = [x["details"]["kind"] for x in entries]
        self.assertIn("inventory_update", kinds)
        self.assertIn("detection_result", kinds)
        self.assertIn("risk_assessment", kinds)
        self.assertIn("snapshot", kinds)
        self.assertEqual(kinds.count("snapshot"), 1)

    def test_details_kind_ist_pflicht(self):
        e = _event("service_started")
        self.ai.process(e)
        for entry in self._read_audit():
            self.assertIn("details", entry)
            self.assertIsInstance(entry["details"], dict)
            self.assertIn("kind", entry["details"])

    def test_snapshot_hash_stabil(self):
        e1 = _event("service_started")
        self.ai.process(e1)
        h1 = [x for x in self._read_audit()
              if x["details"]["kind"] == "snapshot"][-1]["details"]["inventory_hash"]
        e2 = _event("service_started")
        self.ai.process(e2)
        h2 = [x for x in self._read_audit()
              if x["details"]["kind"] == "snapshot"][-1]["details"]["inventory_hash"]
        self.assertEqual(h1, h2)

    def test_inventory_version_gesetzt(self):
        e = _event("service_started")
        self.ai.process(e)
        snap = [x for x in self._read_audit()
                if x["details"]["kind"] == "snapshot"][-1]
        self.assertEqual(snap["details"]["inventory_version"], "0002")

    def test_audit_write_fehler_processing_audit_error(self):
        from harness.audit.writer import AuditWriteError

        class FailingWriter:
            def log(self, *args, **kwargs):
                raise AuditWriteError("simuliert")

        ai = SecurityAI(
            db_path=Path(self.tmp.name) / "inv2.db",
            migrations_dir="data/migrations",
            detection_config_path=RULES_YAML,
            risk_rules_path=RISK_RULES,
            audit_writer=FailingWriter(),
        )
        try:
            e = _event("service_started")
            with self.assertRaises(ProcessingAuditError):
                ai.process(e)
        finally:
            ai.close()

    def test_skip_reports_nicht_geloggt(self):
        e = _event(EventType.DEVICE_PRESENCE.value, data={
            "identifier": "192.168.178.10",
            "network_type": "Hauptnetz",
            "known": True,
        })
        self.ai.process(e)
        entries = self._read_audit()
        rule_ids = [x["details"].get("rule_id") for x in entries
                    if x["details"]["kind"] == "detection_result"]
        self.assertNotIn("port_scan", rule_ids)




if __name__ == "__main__":
    unittest.main()
