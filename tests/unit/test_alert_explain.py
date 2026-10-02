"""Tests fuer core/services/alert_explain.py (Punkt 79)."""
from __future__ import annotations

import unittest

from core.services.alert_explain import (
    RULE_TEMPLATES,
    explain_alert,
)


class ExplainAlertTests(unittest.TestCase):

    def test_explain_known_rules(self):
        for rid in RULE_TEMPLATES:
            out = explain_alert(rid, [])
            self.assertTrue(out)
            self.assertFalse(out.startswith("Regel:"))

    def test_explain_unknown_rule_fallback(self):
        out = explain_alert("unbekannt_xyz", [])
        self.assertEqual(out, "Regel: unbekannt_xyz")

    def test_explain_with_reasons(self):
        out = explain_alert("unknown_device", ["im Hauptnetz"])
        self.assertEqual(
            out, "Unbekanntes Geraet im Hauptnetz (im Hauptnetz)"
        )

    def test_explain_empty_reasons(self):
        out = explain_alert("unknown_device", [])
        self.assertEqual(out, "Unbekanntes Geraet im Hauptnetz")

    def test_explain_none_rule_id(self):
        out = explain_alert(None, [])
        self.assertEqual(out, "Regel unbekannt")


if __name__ == "__main__":
    unittest.main()
