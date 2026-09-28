"""Tests fuer die Risk Engine: Models, Predicates, Engine."""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone, UTC
from pathlib import Path

from core.events.event import Event, EventType, Severity, new_event_id
from core.risk.engine import PREDICATES, RiskEngine
from core.risk.models import (
    DEFAULT_THRESHOLDS,
    RiskAssessment,
    RiskCategory,
    RiskContext,
    RiskRuleError,
    clamp_score,
    score_to_category,
)

RULES_PATH = Path("core/risk/rules.yaml")


def _event(
    event_type: str,
    *,
    data: dict | None = None,
    ts: datetime | None = None,
    source: str = "test",
) -> Event:
    return Event(
        event_id=new_event_id(),
        timestamp=ts or datetime.now(UTC),
        source=source,
        event_type=event_type,
        severity=Severity.INFO,
        data=data or {},
        network_id="homelab-default",
    )


def _ctx(
    *,
    now: datetime | None = None,
    inventory: dict | None = None,
) -> RiskContext:
    return RiskContext(
        now=now or datetime.now(UTC),
        network_id="homelab-default",
        inventory=inventory,
    )


# ---------------------------------------------------------------------- #
# Models
# ---------------------------------------------------------------------- #

class ScoreTests(unittest.TestCase):
    def test_clamp(self):
        self.assertEqual(clamp_score(-0.5), 0.0)
        self.assertEqual(clamp_score(1.5), 1.0)
        self.assertEqual(clamp_score(0.42), 0.42)

    def test_category_defaults(self):
        self.assertIs(score_to_category(0.0), RiskCategory.EVENT)
        self.assertIs(score_to_category(0.19), RiskCategory.EVENT)
        self.assertIs(score_to_category(0.2), RiskCategory.ANOMALY)
        self.assertIs(score_to_category(0.4), RiskCategory.SUSPICION)
        self.assertIs(score_to_category(0.6), RiskCategory.SECURITY_ALERT)
        self.assertIs(score_to_category(0.8), RiskCategory.CONFIRMED)
        self.assertIs(score_to_category(1.0), RiskCategory.CONFIRMED)

    def test_category_custom_thresholds(self):
        th = {"anomaly": 0.1, "suspicion": 0.2,
              "security_alert": 0.3, "confirmed": 0.4}
        self.assertIs(score_to_category(0.35, th), RiskCategory.SECURITY_ALERT)
        self.assertIs(score_to_category(0.40, th), RiskCategory.CONFIRMED)

    def test_category_thresholds_nicht_aufsteigend(self):
        with self.assertRaises(RiskRuleError):
            score_to_category(0.5, {"anomaly": 0.8, "suspicion": 0.4})


class AssessmentTests(unittest.TestCase):
    def test_defaults(self):
        a = RiskAssessment(
            event_id="e", rule_id="r", score=0.5,
            category=RiskCategory.SUSPICION, base=0.4,
            modifiers=[("x", 0.1)],
            reasons=["grund"],
        )
        self.assertEqual(a.modifier_total, 0.1)
        self.assertIsNotNone(a.timestamp.tzinfo)
        out = a.to_dict()
        self.assertEqual(out["category"], "SUSPICION")
        self.assertEqual(out["modifiers"], [["x", 0.1]])

    def test_score_out_of_bounds(self):
        with self.assertRaises(ValueError):
            RiskAssessment(event_id="e", rule_id="r", score=1.2,
                           category=RiskCategory.CONFIRMED, base=0.5)

    def test_naive_timestamp(self):
        with self.assertRaises(ValueError):
            RiskAssessment(event_id="e", rule_id="r", score=0.5,
                           category=RiskCategory.SUSPICION, base=0.5,
                           timestamp=datetime(2026, 1, 1))


class ContextTests(unittest.TestCase):
    def test_leer(self):
        c = RiskContext(now=datetime.now(UTC), network_id="x")
        self.assertFalse(c.is_in_inventory("a"))
        self.assertFalse(c.is_whitelisted("a"))

    def test_gefuellt(self):
        c = RiskContext(
            now=datetime.now(UTC), network_id="x",
            inventory={"devices": {"a"}, "whitelist": {"b"}},
        )
        self.assertTrue(c.is_in_inventory("a"))
        self.assertFalse(c.is_in_inventory("b"))
        self.assertTrue(c.is_whitelisted("b"))
        self.assertFalse(c.is_whitelisted("a"))


# ---------------------------------------------------------------------- #
# Predicates — fail-safe bei fehlenden Feldern
# ---------------------------------------------------------------------- #

class PredicateTests(unittest.TestCase):
    def setUp(self):
        self.ctx = _ctx()

    def test_hauptnetz(self):
        self.assertTrue(PREDICATES["hauptnetz"](
            _event("x", data={"network_type": "Hauptnetz"}), self.ctx))
        self.assertFalse(PREDICATES["hauptnetz"](
            _event("x", data={"network_type": "Gastnetz"}), self.ctx))
        # fehlendes Feld -> False, kein Fehler
        self.assertFalse(PREDICATES["hauptnetz"](_event("x"), self.ctx))

    def test_gastnetz_extern(self):
        self.assertTrue(PREDICATES["gastnetz"](
            _event("x", data={"network_type": "Gastnetz"}), self.ctx))
        self.assertTrue(PREDICATES["extern"](
            _event("x", data={"network_type": "Extern"}), self.ctx))

    def test_nachts(self):
        ts = datetime(2026, 9, 21, 23, 30, tzinfo=UTC)
        self.assertTrue(PREDICATES["nachts"](_event("x", ts=ts), self.ctx))
        ts2 = datetime(2026, 9, 21, 4, 0, tzinfo=UTC)
        self.assertTrue(PREDICATES["nachts"](_event("x", ts=ts2), self.ctx))
        ts3 = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
        self.assertFalse(PREDICATES["nachts"](_event("x", ts=ts3), self.ctx))

    def test_nachts_naive_ts_false(self):
        e = Event(event_id=new_event_id(), timestamp=datetime(2026, 9, 21, 23, 0),
                  source="x", event_type="x", severity=Severity.INFO,
                  data={}, network_id="n")
        self.assertFalse(PREDICATES["nachts"](e, self.ctx))

    def test_wochenende(self):
        # 2026-09-19 ist ein Samstag
        ts = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)
        self.assertTrue(PREDICATES["wochenende"](_event("x", ts=ts), self.ctx))
        ts2 = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)  # Montag
        self.assertFalse(PREDICATES["wochenende"](_event("x", ts=ts2), self.ctx))

    def test_not_in_inventory(self):
        e = _event("x", data={"identifier": "10.0.0.1"})
        self.assertTrue(PREDICATES["not_in_inventory"](e, self.ctx))
        ctx2 = _ctx(inventory={"devices": {"10.0.0.1"}})
        self.assertFalse(PREDICATES["not_in_inventory"](e, ctx2))
        # fehlender identifier -> False
        self.assertFalse(PREDICATES["not_in_inventory"](_event("x"), self.ctx))

    def test_first_seen(self):
        # Feld wird vom Orchestrator gesetzt; Predicate liest nur.
        self.assertTrue(PREDICATES["first_seen"](
            _event("x", data={"first_seen": True}), self.ctx))
        self.assertFalse(PREDICATES["first_seen"](
            _event("x", data={"first_seen": False}), self.ctx))
        # fehlendes Feld -> False (fail safe)
        self.assertFalse(PREDICATES["first_seen"](_event("x"), self.ctx))
        # anderer Typ -> False
        self.assertFalse(PREDICATES["first_seen"](
            _event("x", data={"first_seen": "yes"}), self.ctx))

    def test_is_whitelisted(self):
        e = _event("x", data={"identifier": "10.0.0.1"})
        ctx = _ctx(inventory={"whitelist": {"10.0.0.1"}})
        self.assertTrue(PREDICATES["is_whitelisted"](e, ctx))
        self.assertFalse(PREDICATES["is_whitelisted"](e, self.ctx))

    def test_many_ports_many_ips_brute_force(self):
        e1 = _event(EventType.PORT_SCAN.value, data={"kind": "port_scan"})
        e2 = _event(EventType.PORT_SCAN.value, data={"kind": "network_scan"})
        e3 = _event(EventType.PORT_SCAN.value, data={"kind": "brute_force"})
        self.assertTrue(PREDICATES["many_ports"](e1, self.ctx))
        self.assertTrue(PREDICATES["many_ips"](e2, self.ctx))
        self.assertTrue(PREDICATES["brute_force"](e3, self.ctx))
        # falscher event_type -> False
        e4 = _event("service_started", data={"kind": "port_scan"})
        self.assertFalse(PREDICATES["many_ports"](e4, self.ctx))
        # fehlendes kind -> False
        e5 = _event(EventType.PORT_SCAN.value, data={})
        self.assertFalse(PREDICATES["many_ports"](e5, self.ctx))


# ---------------------------------------------------------------------- #
# Engine
# ---------------------------------------------------------------------- #

class EngineLoadTests(unittest.TestCase):
    def test_rules_yaml_existiert(self):
        self.assertTrue(RULES_PATH.exists())
        engine = RiskEngine(RULES_PATH)
        self.assertIn("unknown_device", engine.known_event_types)
        self.assertIn("port_scan", engine.known_event_types)

    def test_fehlende_yaml(self):
        with self.assertRaises(RiskRuleError):
            RiskEngine("/tmp/does-not-exist-risk.yaml")

    def test_ohne_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "rules.yaml"
            p.write_text(
                "thresholds: {anomaly: 0.2, suspicion: 0.4, security_alert: 0.6, confirmed: 0.8}\n"
                "rules:\n  x:\n    rule_id: x\n    base: 0.1\n    modifiers: []\n",
                encoding="utf-8",
            )
            with self.assertRaises(RiskRuleError):
                RiskEngine(p)

    def test_unbekannter_when(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "rules.yaml"
            p.write_text(
                "default:\n  rule_id: default\n  base: 0.1\n  modifiers: []\n"
                "rules:\n  x:\n    rule_id: x\n    base: 0.1\n    modifiers:\n"
                "      - when: gibt_es_nicht\n        add: 0.1\n",
                encoding="utf-8",
            )
            with self.assertRaises(RiskRuleError):
                RiskEngine(p)


class EngineEvaluateTests(unittest.TestCase):
    def setUp(self):
        self.engine = RiskEngine(RULES_PATH)
        self.now = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)  # Montag, mittags
        self.ctx = _ctx(now=self.now, inventory={"devices": set(), "whitelist": set()})

    def test_default_fuer_unbekannten_typ(self):
        e = _event("service_started", ts=self.now)
        a = self.engine.evaluate(e, self.ctx)
        self.assertIsNotNone(a)
        self.assertEqual(a.rule_id, "default")
        self.assertEqual(a.base, 0.1)
        self.assertIs(a.category, RiskCategory.EVENT)

    def test_unknown_device_base_only(self):
        # nicht nachts, kein Wochenende, nicht im Inventory -> base + not_in_inventory
        e = _event(EventType.UNKNOWN_DEVICE.value, ts=self.now,
                   data={"identifier": "10.0.0.1"})
        a = self.engine.evaluate(e, self.ctx)
        # base 0.5 + not_in_inventory 0.2 = 0.7
        self.assertAlmostEqual(a.score, 0.7, places=4)
        self.assertIs(a.category, RiskCategory.SECURITY_ALERT)
        names = [n for n, _v in a.modifiers]
        self.assertIn("not_in_inventory", names)
        self.assertNotIn("nachts", names)

    def test_unknown_device_hauptnetz_nachts(self):
        ts = datetime(2026, 9, 21, 23, 30, tzinfo=UTC)
        e = _event(EventType.UNKNOWN_DEVICE.value, ts=ts,
                   data={"identifier": "10.0.0.1", "network_type": "Hauptnetz"})
        a = self.engine.evaluate(e, self.ctx)
        # 0.5 + 0.2 + 0.2 + 0.1 = 1.0
        self.assertAlmostEqual(a.score, 1.0, places=4)
        self.assertIs(a.category, RiskCategory.CONFIRMED)

    def test_unknown_device_whitelist_senkt(self):
        e = _event(EventType.UNKNOWN_DEVICE.value, ts=self.now,
                   data={"identifier": "10.0.0.1"})
        ctx = _ctx(now=self.now, inventory={"whitelist": {"10.0.0.1"}})
        a = self.engine.evaluate(e, ctx)
        # 0.5 + not_in_inventory 0.2 + is_whitelisted -0.3 = 0.4
        self.assertAlmostEqual(a.score, 0.4, places=4)
        self.assertIs(a.category, RiskCategory.SUSPICION)

    def test_port_scan_brute_force(self):
        ts = datetime(2026, 9, 21, 23, 30, tzinfo=UTC)
        e = _event(EventType.PORT_SCAN.value, ts=ts,
                   data={"kind": "brute_force"})
        a = self.engine.evaluate(e, self.ctx)
        # 0.4 + 0.5 + 0.1 = 1.0
        self.assertAlmostEqual(a.score, 1.0, places=4)
        names = [n for n, _v in a.modifiers]
        self.assertIn("brute_force", names)
        self.assertIn("nachts", names)

    def test_port_scan_ohne_kind(self):
        e = _event(EventType.PORT_SCAN.value, ts=self.now, data={})
        a = self.engine.evaluate(e, self.ctx)
        # nur base 0.4
        self.assertAlmostEqual(a.score, 0.4, places=4)
        self.assertIs(a.category, RiskCategory.SUSPICION)

    def test_evaluate_ohne_context_baut_default(self):
        e = _event("service_started", ts=self.now)
        a = self.engine.evaluate(e)  # kein Context
        self.assertIsNotNone(a)
        self.assertEqual(a.rule_id, "default")

    def test_reasons_klartext(self):
        e = _event(EventType.UNKNOWN_DEVICE.value, ts=self.now,
                   data={"identifier": "10.0.0.1"})
        a = self.engine.evaluate(e, self.ctx)
        self.assertIn("nicht im Inventory", a.reasons)
        self.assertNotIn("im Hauptnetz", a.reasons)


if __name__ == "__main__":
    unittest.main()
