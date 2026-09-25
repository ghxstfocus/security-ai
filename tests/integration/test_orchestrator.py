"""Integrationstest: Event durch den ganzen Stack (Inventory -> Detection -> Risk)."""
from __future__ import annotations

import json
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

from harness.agent_loop.loop import Plan, PlanStep
from harness.agent_loop.model import BaseModel
from harness.permissions.levels import Level
from harness.tool_registry.registry import ToolRegistry
from harness.tool_registry.tool import Tool
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
        version = snap["details"]["inventory_version"]

        # Format: strikt vierstellig numerisch.
        self.assertRegex(version, r"^\d{4}$")

        # Inhalt: entspricht MAX(version) aus schema_migrations.
        # Vorher stand hier hart "0002" -- der alte Wert, der aus
        # dem defekten Migrations-Tracking stammte (Punkt 15).
        # Nach 3.6.15a traegt apply_migrations die Versionen
        # korrekt ein; ein fester Wert wuerde bei jeder neuen
        # Migration brechen.
        expected = self.ai._conn.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()[0]
        self.assertEqual(version, f"{int(expected):04d}")

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




# ---------------------------------------------------------------------- #
# End-zu-End: Event -> Detection -> Risk -> AgentLoop -> Mock-Tool
# ---------------------------------------------------------------------- #

def _build_test_registry(mock_calls: list) -> ToolRegistry:
    """
    Baut eine Test-Registry mit einem Mock-Tool 'telegram_alert'.

    Der Mock sammelt seine Aufrufe in mock_calls.
    """
    def _mock_telegram(title, message, severity="INFO"):
        mock_calls.append({
            "title": title, "message": message, "severity": severity,
        })
        return {"ok": True, "message_id": len(mock_calls),
                "source": "mock_telegram"}

    reg = ToolRegistry()
    reg.register(Tool(
        name="telegram_alert",
        level=Level.SECURITY_ACTION,
        func=_mock_telegram,
        description="Mock telegram_alert",
        sandbox_profile="no_network_except_telegram",
        allowed_args=frozenset({"title", "message", "severity"}),
    ))
    return reg


_CATEGORY_TO_SEVERITY = {
    "EVENT": "INFO",
    "ANOMALY": "INFO",
    "SUSPICION": "WARNING",
    "SECURITY_ALERT": "WARNING",
    "CONFIRMED": "CRITICAL",
}


class OrchestratorLoopTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit_dir = Path(self.tmp.name) / "audit"
        self.db_path = Path(self.tmp.name) / "inventory.db"
        self.mock_calls: list = []
        self.ai = SecurityAI(
            db_path=self.db_path,
            migrations_dir="data/migrations",
            detection_config_path=RULES_YAML,
            risk_rules_path=RISK_RULES,
            audit_base_dir=self.audit_dir,
            tool_registry=_build_test_registry(self.mock_calls),
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

    def _expected_severity(self, assessment) -> str:
        return _CATEGORY_TO_SEVERITY[assessment.category.value]

    # --- Test 1a: unknown_device, Hauptnetz, nachmittags -> Loop ---

    def test_unknown_device_loest_telegram_alert_aus(self):
        ts = datetime(2026, 9, 21, 14, 0, tzinfo=timezone.utc)
        e = _event(EventType.DEVICE_PRESENCE.value, ts=ts, data={
            "identifier": "192.168.178.77",
            "entity_name": "Neuling",
            "network_type": "Hauptnetz",
            "known": False,
        })
        result = self.ai.process(e)

        # Loop ist gelaufen, genau ein Alert
        self.assertEqual(len(result.loop_results), 1)
        self.assertEqual(result.loop_results[0].status, "OK")
        self.assertEqual(len(result.assessments), 1)

        # Mock wurde genau 1x gerufen, Severity abgeleitet
        self.assertEqual(len(self.mock_calls), 1)
        call = self.mock_calls[0]
        self.assertEqual(call["severity"], self._expected_severity(
            result.assessments[0]))
        self.assertIn("192.168.178.77", call["title"])
        self.assertIn("message", call)

        # Audit: loop_result + tool_call
        entries = self._read_audit()
        kinds = [x["details"]["kind"] for x in entries]
        self.assertIn("loop_result", kinds)
        self.assertIn("tool_call", kinds)
        tc = [x for x in entries if x["details"]["kind"] == "tool_call"][0]
        self.assertEqual(tc["details"]["tool"], "telegram_alert")
        self.assertEqual(tc["details"]["level"], int(Level.SECURITY_ACTION))

    # --- Test 1b: bekanntes Geraet -> kein Loop ---

    def test_bekanntes_geraet_kein_loop(self):
        ts = datetime(2026, 9, 21, 14, 0, tzinfo=timezone.utc)
        # Geraet zuerst in die DB bringen
        self.ai.devices.upsert_seen(
            "192.168.178.10",
            entity_name="Bekannt",
            network_type="Hauptnetz",
            timestamp=ts,
        )
        # dann device_presence mit known=True
        e = _event(EventType.DEVICE_PRESENCE.value, ts=ts, data={
            "identifier": "192.168.178.10",
            "network_type": "Hauptnetz",
            "known": True,
        })
        result = self.ai.process(e)
        self.assertEqual(result.loop_results, [])
        self.assertEqual(self.mock_calls, [])

    # --- Test 2: Gastnetz -> kein Loop ---

    def test_gastnetz_kein_loop(self):
        ts = datetime(2026, 9, 21, 14, 0, tzinfo=timezone.utc)
        e = _event(EventType.DEVICE_PRESENCE.value, ts=ts, data={
            "identifier": "192.168.179.5",
            "entity_name": "Gast-Phone",
            "network_type": "Gastnetz",
            "known": False,
        })
        result = self.ai.process(e)
        self.assertEqual(result.loop_results, [])
        self.assertEqual(self.mock_calls, [])

    # --- Test 3: Port-Scan -> Loop ---

    def test_port_scan_loest_telegram_alert_aus(self):
        base = datetime(2026, 9, 21, 14, 0, tzinfo=timezone.utc)
        results = []
        for i in range(15):
            e = _event(EventType.SYN_PACKET.value,
                       ts=base + timedelta(seconds=i), data={
                "src_ip": "192.168.178.87",
                "dst_ip": "192.168.178.1",
                "dst_port": 2000 + i,
                "protocol": "tcp",
            })
            results.append(self.ai.process(e))

        all_loops = [lr for r in results for lr in r.loop_results]
        all_assessments = [a for r in results for a in r.assessments]
        self.assertGreaterEqual(len(all_loops), 1)
        self.assertEqual(all_loops[0].status, "OK")
        self.assertEqual(len(self.mock_calls), 1)
        # Severity abgeleitet aus Assessment-Kategorie
        self.assertEqual(self.mock_calls[0]["severity"],
                         self._expected_severity(all_assessments[0]))

    # --- Test 4: Brute-Force -> Loop mit CRITICAL ---

    def test_brute_force_loest_telegram_alert_aus(self):
        base = datetime(2026, 9, 21, 14, 0, tzinfo=timezone.utc)
        results = []
        for i in range(25):
            e = _event(EventType.SYN_PACKET.value,
                       ts=base + timedelta(seconds=i * 0.5), data={
                "src_ip": "192.168.178.87",
                "dst_ip": "192.168.178.1",
                "dst_port": 22,   # immer derselbe Port
                "protocol": "tcp",
            })
            results.append(self.ai.process(e))

        all_loops = [lr for r in results for lr in r.loop_results]
        all_assessments = [a for r in results for a in r.assessments]
        self.assertGreaterEqual(len(all_loops), 1)
        self.assertGreaterEqual(len(self.mock_calls), 1)

        # kind=brute_force -> SecurityPlanModel zieht Severity auf CRITICAL
        # Assessment-Kategorie sollte CONFIRMED sein
        self.assertEqual(all_assessments[0].category.value, "CONFIRMED")
        self.assertEqual(self.mock_calls[0]["severity"], "CRITICAL")



if __name__ == "__main__":
    unittest.main()

# ---------------------------------------------------------------------- #
# Approval-Flow (Phase 4-Haertung)
# ---------------------------------------------------------------------- #

def _build_approval_test_registry(mock_calls: list) -> ToolRegistry:
    """
    Test-Registry mit telegram_alert (Mock) und nmap_scan (Mock, Level 4).

    nmap_scan ist Level.SECURITY_ACTION -> requires_approval.
    Ziel 10.0.0.1 ist nicht in authorized_networks, daher Policy
    APPROVAL_REQUIRED. Beides fuehrt in den Approval-Pfad.
    """
    def _mock_telegram(title, message, severity="INFO"):
        mock_calls.append({
            "tool": "telegram_alert",
            "title": title, "message": message, "severity": severity,
        })
        return {"ok": True, "message_id": len(mock_calls),
                "source": "mock_telegram"}

    def _mock_nmap(target, ports=None, scan_type="connect"):
        mock_calls.append({
            "tool": "nmap_scan",
            "target": target, "ports": ports, "scan_type": scan_type,
        })
        return {"source": "mock_nmap", "hosts": []}

    reg = ToolRegistry()
    reg.register(Tool(
        name="telegram_alert",
        level=Level.SECURITY_ACTION,
        func=_mock_telegram,
        description="Mock telegram_alert",
        sandbox_profile="no_network_except_telegram",
        allowed_args=frozenset({"title", "message", "severity"}),
    ))
    reg.register(Tool(
        name="nmap_scan",
        level=Level.SECURITY_ACTION,
        func=_mock_nmap,
        description="Mock nmap_scan",
        sandbox_profile="nmap_local",
        allowed_args=frozenset({"target", "ports", "scan_type"}),
    ))
    return reg


class NmapPlanModel(BaseModel):
    """Liefert einen nmap_scan-Step auf ein nicht autorisiertes Ziel."""

    def plan(self, event, context):
        return Plan(steps=[
            PlanStep(
                tool="nmap_scan",
                args={"target": "10.0.0.1", "scan_type": "connect"},
                reason="test",
            ),
        ], summary="approval flow test")


class ApprovalFlowIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.audit_dir = self.tmp_path / "audit-logs"
        self.mock_calls: list = []
        self.registry = _build_approval_test_registry(self.mock_calls)
        self.ai = SecurityAI(
            db_path=self.tmp_path / "inventory.db",
            migrations_dir="data/migrations",
            detection_config_path=RULES_YAML,
            risk_rules_path=RISK_RULES,
            audit_base_dir=self.audit_dir,
            tool_registry=self.registry,
            plan_model=NmapPlanModel(),
            approval_notify_enabled=True,
            app_config_path=self.tmp_path / "cfg.yaml",
        )

    def tearDown(self):
        self.ai.close()
        self.tmp.cleanup()

    def _read_audit_kinds(self) -> list:
        """Liest die heutige Audit-JSONL und liefert details.kind-Werte."""
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        f = self.audit_dir / f"{today}.jsonl"
        if not f.exists():
            return []
        kinds = []
        for line in f.read_text().splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            details = entry.get("details") or {}
            kinds.append(details.get("kind"))
        return kinds

    def test_approval_flow_alert_und_approval_benachrichtigung(self):
        # Event wie in OrchestratorLoopTests.test_unknown_device_loest_-
        # telegram_alert_aus: DEVICE_PRESENCE, Hauptnetz, known=False.
        # Das triggert Detection + Risk + Loop.
        ts = datetime(2026, 9, 21, 14, 0, tzinfo=timezone.utc)
        ev = _event(
            EventType.DEVICE_PRESENCE.value,
            ts=ts,
            data={
                "identifier": "192.168.178.77",
                "entity_name": "Neuling",
                "network_type": "Hauptnetz",
                "known": False,
            },
        )
        # telegram_alert_run wird gemockt: der Approval-Hook im
        # Orchestrator ruft das Tool direkt, nicht ueber die Registry.
        with mock.patch(
            "apps.security_ai.orchestrator.telegram_alert_run"
        ) as tg:
            result = self.ai.process(ev)

        # Loop ist pausiert
        self.assertEqual(len(result.loop_results), 1)
        lr = result.loop_results[0]
        self.assertEqual(lr.status, "APPROVAL_REQUIRED")
        self.assertIsNotNone(lr.approval_request_id)

        # Approval liegt in der DB
        pending = self.ai._approval_queue.pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].request_id, lr.approval_request_id)
        self.assertEqual(pending[0].status.value, "pending")

        # Audit-Kinds
        kinds = self._read_audit_kinds()
        self.assertIn("tool_approval_required", kinds)
        self.assertIn("approval_requested", kinds)
        self.assertIn("approval_notify_sent", kinds)
        self.assertIn("loop_result", kinds)

        # Approval-Notification hat telegram_alert_run gerufen
        self.assertEqual(tg.call_count, 1)
        kwargs = tg.call_args.kwargs
        self.assertIn(f"/approve {lr.approval_request_id}",
                      kwargs["message"])
        self.assertIn(f"/reject {lr.approval_request_id}",
                      kwargs["message"])
        self.assertEqual(kwargs["severity"], "WARNING")
        # nmap_scan wurde NICHT gerufen (Approval blockiert)
        nmap_calls = [
            c for c in self.mock_calls if c["tool"] == "nmap_scan"
        ]
        self.assertEqual(nmap_calls, [])
