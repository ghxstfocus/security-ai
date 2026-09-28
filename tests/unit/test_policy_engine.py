"""Tests fuer die Policy Engine: Models, Pruefer, evaluate()."""
from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from harness.policy_engine.engine import (
    GLOBAL_PREDICATES,
    SPECIFIC_PREDICATES,
    PolicyEngine,
    all_predicate_names,
    get_predicate,
)
from harness.policy_engine.policy import (
    Decision,
    PolicyContext,
    PolicyDecision,
    PolicyError,
    PredicateResult,
    allowed,
    approval,
    forbidden,
    strictest,
)

RULES_PATH = Path("policies/tools.yaml")


def _ctx(**kwargs) -> PolicyContext:
    defaults = {
        "network_id": "homelab-default",
        "authorized_networks": frozenset({"192.168.178.0/24"}),
        "now": datetime.now(UTC),
        "config": {"read_only_paths": ["/var/log"]},
    }
    defaults.update(kwargs)
    return PolicyContext(**defaults)


# ---------------------------------------------------------------------- #
# Modelle
# ---------------------------------------------------------------------- #

class DecisionTests(unittest.TestCase):
    def test_strictest(self):
        self.assertIs(strictest(Decision.ALLOWED, Decision.FORBIDDEN),
                      Decision.FORBIDDEN)
        self.assertIs(strictest(Decision.APPROVAL_REQUIRED, Decision.ALLOWED),
                      Decision.APPROVAL_REQUIRED)
        self.assertIs(strictest(Decision.APPROVAL_REQUIRED, Decision.FORBIDDEN),
                      Decision.FORBIDDEN)


class PredicateResultTests(unittest.TestCase):
    def test_on_fail_darf_nicht_allowed_sein(self):
        with self.assertRaises(PolicyError):
            PredicateResult(passed=False, on_fail=Decision.ALLOWED)

    def test_default(self):
        r = PredicateResult(passed=True)
        self.assertTrue(r.passed)


class PolicyDecisionTests(unittest.TestCase):
    def test_level_validierung(self):
        with self.assertRaises(PolicyError):
            PolicyDecision(decision=Decision.ALLOWED, reason="x",
                           matched_rule=None, tool_name="x", level=9)

    def test_fabriken(self):
        a = allowed("x")
        self.assertTrue(a.is_allowed)
        self.assertEqual(a.reason, "alle Bedingungen erfuellt")
        f = forbidden("x", "nope")
        self.assertTrue(f.is_forbidden)
        ap = approval("x", "manual", failed=["p"])
        self.assertTrue(ap.needs_approval)
        self.assertEqual(ap.failed_predicates, ["p"])


class PredicateRegistryTests(unittest.TestCase):
    def test_global_und_specific_getrennt(self):
        self.assertIn("no_shell_chars", GLOBAL_PREDICATES)
        self.assertIn("no_path_traversal", GLOBAL_PREDICATES)
        self.assertIn("no_null_bytes", GLOBAL_PREDICATES)
        self.assertIn("authorized_target", SPECIFIC_PREDICATES)
        self.assertIn("read_only_path", SPECIFIC_PREDICATES)
        self.assertNotIn("no_shell_chars", SPECIFIC_PREDICATES)

    def test_all_predicate_names(self):
        names = all_predicate_names()
        self.assertIn("no_shell_chars", names)
        self.assertIn("authorized_target", names)

    def test_get_predicate(self):
        _fn, kind = get_predicate("no_shell_chars")
        self.assertEqual(kind, "global")
        _fn, kind = get_predicate("authorized_target")
        self.assertEqual(kind, "specific")
        with self.assertRaises(PolicyError):
            get_predicate("gibt_es_nicht")


# ---------------------------------------------------------------------- #
# Engine: Laden
# ---------------------------------------------------------------------- #

class EngineLoadTests(unittest.TestCase):
    def test_rules_yaml_existiert(self):
        self.assertTrue(RULES_PATH.exists())
        eng = PolicyEngine(RULES_PATH)
        self.assertTrue(eng.has_tool("nmap_scan"))
        self.assertTrue(eng.has_tool("read_logs"))

    def test_fehlende_datei(self):
        with self.assertRaises(PolicyError):
            PolicyEngine("/tmp/does-not-exist-policies.yaml")

    def test_unbekannter_pruefer(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad.yaml"
            p.write_text(
                "tools:\n  x:\n    allowed: true\n"
                "    conditions: [gibt_es_nicht]\n",
                encoding="utf-8",
            )
            with self.assertRaises(PolicyError):
                PolicyEngine(p)

    def test_globaler_pruefer_in_conditions_verboten(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad.yaml"
            p.write_text(
                "tools:\n  x:\n    allowed: true\n"
                "    conditions: [no_shell_chars]\n",
                encoding="utf-8",
            )
            with self.assertRaises(PolicyError):
                PolicyEngine(p)

    def test_forbidden_args_muss_strings_sein(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad.yaml"
            p.write_text(
                "tools:\n  x:\n    allowed: true\n"
                "    forbidden_args: [1, 2]\n",
                encoding="utf-8",
            )
            with self.assertRaises(PolicyError):
                PolicyEngine(p)


# ---------------------------------------------------------------------- #
# Engine: evaluate()
# ---------------------------------------------------------------------- #

class EngineEvaluateTests(unittest.TestCase):
    def setUp(self):
        self.eng = PolicyEngine(RULES_PATH)
        self.ctx = _ctx()

    # --- Grundlagen ---

    def test_tool_nicht_in_policy_forbidden(self):
        d = self.eng.evaluate("gibt_es_nicht", {}, self.ctx)
        self.assertTrue(d.is_forbidden)
        self.assertIn("nicht in Policy", d.reason)

    def test_tool_ohne_conditions_allowed(self):
        d = self.eng.evaluate("get_devices", {}, self.ctx)
        self.assertTrue(d.is_allowed)
        self.assertEqual(d.reason, "keine Conditions definiert")

    # --- Globale Pruefer ---

    def test_shell_zeichen_global_forbidden(self):
        d = self.eng.evaluate(
            "read_logs", {"path": "/var/log/syslog; rm -rf /"}, self.ctx
        )
        self.assertTrue(d.is_forbidden)
        self.assertIn("no_shell_chars", d.failed_predicates)

    def test_path_traversal_global_forbidden(self):
        d = self.eng.evaluate(
            "read_logs", {"path": "../../etc/shadow"}, self.ctx
        )
        self.assertTrue(d.is_forbidden)
        self.assertIn("no_path_traversal", d.failed_predicates)

    def test_null_byte_global_forbidden(self):
        d = self.eng.evaluate(
            "read_logs", {"path": "/var/log/syslog\x00"}, self.ctx
        )
        self.assertTrue(d.is_forbidden)
        self.assertIn("no_null_bytes", d.failed_predicates)

    def test_globaler_pruefer_greift_ohne_conditions(self):
        # get_devices hat keine conditions, aber global greift trotzdem.
        d = self.eng.evaluate("get_devices", {"x": "a; b"}, self.ctx)
        self.assertTrue(d.is_forbidden)
        self.assertIn("no_shell_chars", d.failed_predicates)

    # --- forbidden_args ---

    def test_forbidden_args_schlaegt_frueh_zu(self):
        d = self.eng.evaluate(
            "nmap_scan",
            {"target": "192.168.178.0/24", "--script": "vuln"},
            self.ctx,
        )
        self.assertTrue(d.is_forbidden)
        self.assertIn("forbidden_args", d.failed_predicates)

    # --- Spezifische Pruefer ---

    def test_nmap_autorisiert_allowed(self):
        d = self.eng.evaluate(
            "nmap_scan", {"target": "192.168.178.0/24"}, self.ctx
        )
        self.assertTrue(d.is_allowed)
        self.assertEqual(d.reason, "alle Bedingungen erfuellt")

    def test_nmap_nicht_autorisiert_approval_required(self):
        d = self.eng.evaluate("nmap_scan", {"target": "10.0.0.1"}, self.ctx)
        self.assertTrue(d.needs_approval)
        self.assertIn("authorized_target", d.failed_predicates)

    def test_read_logs_ok_allowed(self):
        d = self.eng.evaluate(
            "read_logs", {"path": "/var/log/syslog"}, self.ctx
        )
        self.assertTrue(d.is_allowed)

    def test_read_logs_pfad_ausserhalb_approval_required(self):
        d = self.eng.evaluate(
            "read_logs", {"path": "/etc/passwd"}, self.ctx
        )
        self.assertTrue(d.needs_approval)
        self.assertIn("read_only_path", d.failed_predicates)

    def test_telegram_alert_normale_nachricht(self):
        d = self.eng.evaluate(
            "telegram_alert", {"text": "hallo welt"}, self.ctx
        )
        self.assertTrue(d.is_allowed)

    def test_telegram_alert_mit_shell_forbidden(self):
        d = self.eng.evaluate(
            "telegram_alert", {"text": "hi; rm -rf /"}, self.ctx
        )
        self.assertTrue(d.is_forbidden)


if __name__ == "__main__":
    unittest.main()
