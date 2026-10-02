# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tests fuer die Chat-Klassifikation (3.6.15d).

Kategorie 3, Auflagen 507-522.

Deckt ab:
- F1 (A513): _classify_question: fact > concept > interpretation,
  concept nur, wenn nicht Zustandsfrage.
- F2 (A514): _STATE_QUESTION_RE erweitert.
- F3 (A507): Auto-Switch bei jeder Interpretation mit kritischen
  Assessments.
- A515/A516: "Was ist der Status?" / "Was ist heute Nacht passiert?"
  sind interpretation.
- A517: Concept-Frage mit kritischen Assessments bleibt 3B.
- A519: model_reason konsistent (fact, detail_append, no_context,
  default, auto_critical_state, concept).
"""
from __future__ import annotations

import unittest

from apps.security_ai.chat import (
    _classify_question,
    _has_critical_assessments,
    _is_state_question,
)
from harness.context.models import ContextBundle, utc_now


class ClassifyTests(unittest.TestCase):
    # A513: fact > concept > interpretation
    def test_was_ist_heute_nacht_passiert_is_interpretation(self):
        self.assertEqual(
            _classify_question("Was ist heute Nacht passiert?"),
            "interpretation",
        )

    def test_was_ist_der_status_is_interpretation(self):
        self.assertEqual(
            _classify_question("Was ist der Status?"),
            "interpretation",
        )

    def test_was_ist_ein_portscan_is_concept(self):
        self.assertEqual(
            _classify_question("Was ist ein Portscan?"),
            "concept",
        )

    def test_was_bedeutet_confirmed_is_concept(self):
        self.assertEqual(
            _classify_question("Was bedeutet CONFIRMED?"),
            "concept",
        )

    def test_gab_es_auffaelligkeiten_is_fact(self):
        self.assertEqual(
            _classify_question("Gab es Auffaelligkeiten?"),
            "fact",
        )

    def test_wie_viele_events_is_fact(self):
        self.assertEqual(
            _classify_question("Wie viele Events gab es?"),
            "fact",
        )

    def test_sind_kritische_alarme_da_is_state(self):
        self.assertTrue(
            _is_state_question("Sind kritische Alarme da?")
        )

    def test_hat_es_vorfaelle_gegeben_is_state(self):
        self.assertTrue(
            _is_state_question("Hat es Vorfaelle gegeben?")
        )

    def test_sind_kritische_alarme_da_is_interpretation(self):
        # kein FACT_RE, kein CONCEPT_RE -> interpretation
        self.assertEqual(
            _classify_question("Sind kritische Alarme da?"),
            "interpretation",
        )

    def test_hat_es_vorfaelle_gegeben_is_interpretation(self):
        self.assertEqual(
            _classify_question("Hat es Vorfaelle gegeben?"),
            "interpretation",
        )

    # A807 (Punkt 32): "gibt es" im fact-Pfad, aber nur ohne
    # Bewertungswort (_has_critical_state_word als Veto).
    def test_gibt_es_auffaelligkeiten_is_fact(self):
        self.assertEqual(
            _classify_question("Gibt es Auffaelligkeiten?"),
            "fact",
        )

    def test_gibt_es_portscans_is_fact(self):
        self.assertEqual(
            _classify_question("Gibt es Portscans?"),
            "fact",
        )

    def test_gibt_es_mit_kontext_is_fact(self):
        self.assertEqual(
            _classify_question("Gibt es neue Geraete?"),
            "fact",
        )

    def test_gibt_es_derzeit_auffaelligkeiten_is_fact(self):
        self.assertEqual(
            _classify_question("Gibt es derzeit Auffaelligkeiten?"),
            "fact",
        )

    def test_gibt_es_kritische_alarme_is_interpretation(self):
        self.assertEqual(
            _classify_question("Gibt es kritische Alarme?"),
            "interpretation",
        )

    def test_gibt_es_vorfaelle_is_interpretation(self):
        self.assertEqual(
            _classify_question("Gibt es Vorfaelle?"),
            "interpretation",
        )

    def test_gibt_es_aktuell_kritische_alarme_is_interpretation(self):
        self.assertEqual(
            _classify_question("Gibt es aktuell kritische Alarme?"),
            "interpretation",
        )


class ModelReasonConsistencyTests(unittest.TestCase):
    """A519: model_reason-Werte konsistent."""

    def test_fact_path_has_reason_fact(self):
        # Der fact-Pfad setzt model_reason="fact" (bereits vor
        # 3.6.15d). Der Test schuetzt vor Regression.
        import inspect

        from apps.security_ai.chat import ChatService
        src = inspect.getsource(ChatService.ask)
        self.assertIn('model_reason="fact"', src)

    def test_no_context_path_has_reason_no_context(self):
        import inspect

        from apps.security_ai.chat import ChatService
        src = inspect.getsource(ChatService.ask)
        self.assertIn('model_reason="no_context"', src)

    def test_detail_path_has_reason_detail_append(self):
        import inspect

        from apps.security_ai.chat import ChatService
        src = inspect.getsource(ChatService.ask)
        self.assertIn('model_reason="detail_append"', src)


class CriticalAssessmentsTests(unittest.TestCase):
    """A508: nur CONFIRMED und SECURITY_ALERT zaehlen."""

    def _ctx(self, categories):
        class _RA:
            def __init__(self, c):
                self.category = c

        return ContextBundle(
            built_at=utc_now(),
            risk_assessments=tuple(_RA(c) for c in categories),
        )

    def test_confirmed_zaehlt(self):
        self.assertTrue(
            _has_critical_assessments(self._ctx(["CONFIRMED"]))
        )

    def test_security_alert_zaehlt(self):
        self.assertTrue(
            _has_critical_assessments(self._ctx(["SECURITY_ALERT"]))
        )

    def test_suspicion_zaehlt_nicht(self):
        self.assertFalse(
            _has_critical_assessments(self._ctx(["SUSPICION"]))
        )

    def test_anomaly_zaehlt_nicht(self):
        self.assertFalse(
            _has_critical_assessments(self._ctx(["ANOMALY"]))
        )


class AutoSwitchTests(unittest.TestCase):
    """A507/A509: Auto-Switch bei Interpretation mit kritischen
    Assessments -> model_reason="auto_critical_state".
    A517: Concept-Frage bleibt 3B.
    """

    def _make_service(self):
        from apps.security_ai.chat import ChatService

        class _Audit:
            def log(self, **kw):
                pass

        class _LLM:
            def generate(self, req):
                raise AssertionError("LLM darf nicht gerufen werden")

        class _Checker:
            def role_of(self, name):
                return None

            def require_permission(self, name, code):
                pass

        return ChatService(
            audit_writer=_Audit(),
            llm_client=_LLM(),
            checker=_Checker(),
            default_model="llama3.2:3b",
            large_model="qwen2.5:7b",
        )

    def _ctx(self, categories):
        class _RA:
            def __init__(self, c):
                self.category = c

        return ContextBundle(
            built_at=utc_now(),
            risk_assessments=tuple(_RA(c) for c in categories),
        )

    def test_interpretation_mit_kritischen_assessments_switched(self):
        svc = self._make_service()
        ctx = self._ctx(["CONFIRMED"] * 91)
        model, reason, _ = svc._select_model(
            "Sind kritische Alarme da?", ctx, None,
        )
        self.assertEqual(model, "qwen2.5:7b")
        self.assertEqual(reason, "auto_critical_state")

    def test_interpretation_ohne_kritische_assessments_bleibt_default(self):
        svc = self._make_service()
        ctx = self._ctx(["SUSPICION", "ANOMALY"])
        model, reason, _ = svc._select_model(
            "Sind kritische Alarme da?", ctx, None,
        )
        self.assertEqual(model, "llama3.2:3b")
        self.assertEqual(reason, "default")

    def test_concept_frage_mit_kritischen_assessments_bleibt_3b(self):
        svc = self._make_service()
        ctx = self._ctx(["CONFIRMED"] * 91)
        model, reason, _ = svc._select_model(
            "Was ist ein Portscan?", ctx, None,
        )
        self.assertEqual(model, "llama3.2:3b")
        self.assertEqual(reason, "concept")

    def test_was_ist_heute_nacht_switched(self):
        svc = self._make_service()
        ctx = self._ctx(["CONFIRMED"] * 91)
        model, reason, _ = svc._select_model(
            "Was ist heute Nacht passiert?", ctx, None,
        )
        self.assertEqual(model, "qwen2.5:7b")
        self.assertEqual(reason, "auto_critical_state")

    def test_was_ist_der_status_switched(self):
        svc = self._make_service()
        ctx = self._ctx(["SECURITY_ALERT"] * 10)
        model, reason, _ = svc._select_model(
            "Was ist der Status?", ctx, None,
        )
        self.assertEqual(model, "qwen2.5:7b")
        self.assertEqual(reason, "auto_critical_state")


if __name__ == "__main__":
    unittest.main()
