"""
Tests fuer SecurityPlanModel.

Ebene 2: prueft das Mapping Risk-Category -> Plan isoliert.
Kein Orchestrator, kein AgentLoop, keine Detection.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timezone

from apps.security_ai.planning import SecurityPlanModel
from core.events.event import Event, Severity, new_event_id


def _event(event_type: str, data: dict) -> Event:
    return Event(
        event_id=new_event_id(),
        timestamp=datetime.now(timezone.utc),
        source="test",
        event_type=event_type,
        severity=Severity.INFO,
        data=data,
        network_id="homelab-default",
    )


class SecurityPlanModelTests(unittest.TestCase):
    def setUp(self):
        self.model = SecurityPlanModel()

    # --- Grundregel: nur SECURITY_ALERT und CONFIRMED ---

    def test_security_alert_erzeugt_plan(self):
        e = _event("unknown_device", {
            "identifier": "192.168.178.87",
            "risk_category": "SECURITY_ALERT",
            "risk_score": 0.7,
        })
        plan = self.model.plan(e, {})
        self.assertEqual(len(plan.steps), 1)
        self.assertEqual(plan.steps[0].tool, "telegram_alert")
        self.assertEqual(plan.steps[0].args["severity"], "WARNING")

    def test_confirmed_erzeugt_plan(self):
        e = _event("unknown_device", {
            "identifier": "192.168.178.87",
            "risk_category": "CONFIRMED",
            "risk_score": 0.95,
        })
        plan = self.model.plan(e, {})
        self.assertEqual(len(plan.steps), 1)
        self.assertEqual(plan.steps[0].args["severity"], "CRITICAL")

    def test_suspicion_kein_plan(self):
        e = _event("unknown_device", {
            "identifier": "x",
            "risk_category": "SUSPICION",
            "risk_score": 0.5,
        })
        plan = self.model.plan(e, {})
        self.assertEqual(plan.steps, [])

    def test_anomaly_kein_plan(self):
        e = _event("unknown_device", {
            "risk_category": "ANOMALY", "risk_score": 0.3,
        })
        self.assertEqual(self.model.plan(e, {}).steps, [])

    def test_event_kein_plan(self):
        e = _event("unknown_device", {
            "risk_category": "EVENT", "risk_score": 0.1,
        })
        self.assertEqual(self.model.plan(e, {}).steps, [])

    def test_kein_risk_category_kein_plan(self):
        e = _event("unknown_device", {"identifier": "x"})
        self.assertEqual(self.model.plan(e, {}).steps, [])

    def test_unbekannte_kategorie_kein_plan(self):
        e = _event("unknown_device", {
            "risk_category": "GIBT_ES_NICHT",
            "risk_score": 0.9,
        })
        self.assertEqual(self.model.plan(e, {}).steps, [])

    # --- kind=brute_force/network_scan zieht Severity auf CRITICAL ---

    def test_brute_force_wird_critical(self):
        # auch bei SECURITY_ALERT (nicht CONFIRMED)
        e = _event("port_scan", {
            "src_ip": "10.0.0.5",
            "kind": "brute_force",
            "risk_category": "SECURITY_ALERT",
            "risk_score": 0.7,
        })
        plan = self.model.plan(e, {})
        self.assertEqual(len(plan.steps), 1)
        self.assertEqual(plan.steps[0].args["severity"], "CRITICAL")

    def test_network_scan_wird_critical(self):
        e = _event("port_scan", {
            "src_ip": "10.0.0.5",
            "kind": "network_scan",
            "risk_category": "SECURITY_ALERT",
            "risk_score": 0.7,
        })
        plan = self.model.plan(e, {})
        self.assertEqual(plan.steps[0].args["severity"], "CRITICAL")

    def test_port_scan_bleibt_warning(self):
        # kind=port_scan zieht NICHT auf CRITICAL
        e = _event("port_scan", {
            "src_ip": "10.0.0.5",
            "kind": "port_scan",
            "risk_category": "SECURITY_ALERT",
            "risk_score": 0.7,
        })
        plan = self.model.plan(e, {})
        self.assertEqual(plan.steps[0].args["severity"], "WARNING")

    # --- Args-Struktur ---

    def test_args_enthalten_title_message_severity(self):
        e = _event("unknown_device", {
            "identifier": "192.168.178.87",
            "entity_name": "Ghxst-Server",
            "network_type": "Hauptnetz",
            "risk_category": "CONFIRMED",
            "risk_score": 0.95,
        })
        plan = self.model.plan(e, {})
        args = plan.steps[0].args
        self.assertIn("title", args)
        self.assertIn("message", args)
        self.assertIn("severity", args)
        self.assertIn("192.168.178.87", args["title"])
        self.assertIn("Ghxst-Server", args["message"])
        self.assertIn("Hauptnetz", args["message"])
        self.assertIn("CONFIRMED", args["message"])

    def test_reason_enthaelt_category_und_score(self):
        e = _event("unknown_device", {
            "identifier": "x",
            "risk_category": "SECURITY_ALERT",
            "risk_score": 0.72,
        })
        plan = self.model.plan(e, {})
        reason = plan.steps[0].reason
        self.assertIn("SECURITY_ALERT", reason)
        self.assertIn("0.72", reason)

    def test_summary_enthaelt_severity_und_title(self):
        e = _event("unknown_device", {
            "identifier": "x",
            "risk_category": "CONFIRMED",
            "risk_score": 0.95,
        })
        plan = self.model.plan(e, {})
        self.assertIn("CRITICAL", plan.summary)


if __name__ == "__main__":
    unittest.main()
