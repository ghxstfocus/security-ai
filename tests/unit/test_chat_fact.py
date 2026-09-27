"""
Tests fuer den Fact-Antwort-Stil (Punkt 31).

Auflagen 821-825, 830-832, 839-841, 852.

Deckt ab:
- A821/A824: Anzeige-Labels statt Rohkategorien.
- A825: "Assessments" -> "Vorkommen".
- A839/A840: _format_hours-Matrix.
- A852: ChatService.ask(..., since_hours=) an Builder.
"""
from __future__ import annotations

import unittest

from apps.security_ai.chat import (
    ChatService,
    _answer_fact,
    _format_hours,
)
from core.risk.models import CATEGORY_LABELS
from harness.context.models import ContextBundle, utc_now


class _RA:
    """Test-Double fuer RiskAssessment (nur .category)."""

    def __init__(self, category: str) -> None:
        self.category = category


def _ctx(categories, since_hours=24):
    return ContextBundle(
        built_at=utc_now(),
        since_hours=since_hours,
        risk_assessments=tuple(_RA(c) for c in categories),
    )


class FactLabelsTests(unittest.TestCase):
    """A821/A824/A825: Labels, Schweregrad-Reihenfolge, Vorkommen."""

    def test_confirmed_und_security_alert_mit_labels(self):
        text = _answer_fact(
            "Gibt es Auffaelligkeiten?",
            _ctx(["CONFIRMED", "SECURITY_ALERT"]),
        )
        self.assertIn("Kritisch=1", text)
        self.assertIn("Alarm=1", text)
        # A821: keine Rohkategorien.
        self.assertNotIn("CONFIRMED=", text)
        self.assertNotIn("SECURITY_ALERT=", text)
        # A825: Vorkommen statt Assessments.
        self.assertIn("Vorkommen", text)
        self.assertNotIn("Assessments", text)

    def test_nur_suspicion_wird_warnung(self):
        text = _answer_fact(
            "Gibt es Auffaelligkeiten?",
            _ctx(["SUSPICION"]),
        )
        self.assertIn("Warnung=1", text)
        self.assertNotIn("SUSPICION=", text)

    def test_zeitraum_default_24(self):
        text = _answer_fact(
            "Gibt es Auffaelligkeiten?",
            _ctx(["CONFIRMED"]),
        )
        self.assertIn("in den letzten 24 Stunden", text)


class FormatHoursTests(unittest.TestCase):
    """A839/A840: Zeitraum-Anzeige."""

    def test_stunden_und_tage(self):
        self.assertEqual(
            _format_hours(1), "in der letzten Stunde"
        )
        self.assertEqual(
            _format_hours(2), "in den letzten 2 Stunden"
        )
        self.assertEqual(
            _format_hours(23), "in den letzten 23 Stunden"
        )
        self.assertEqual(
            _format_hours(24), "in den letzten 24 Stunden"
        )
        self.assertEqual(
            _format_hours(48), "in den letzten 2 Tagen"
        )
        self.assertEqual(
            _format_hours(72), "in den letzten 3 Tagen"
        )
        self.assertEqual(
            _format_hours(168), "in den letzten 7 Tagen"
        )


class _FakeBuilder:
    """Builder-Double: merkt sich since_hours."""

    def __init__(self):
        self.seen_since_hours = None

    def build(self, **kwargs):
        self.seen_since_hours = kwargs.get("since_hours")
        return ContextBundle(
            built_at=utc_now(),
            since_hours=kwargs.get("since_hours", 24),
        )


class _FakeChecker:
    def role_of(self, name):
        return "admin"

    def require_permission(self, name, code):
        return None

    def check(self, name, code):
        return True


class _FakeAudit:
    def log(self, *a, **k):
        return None


class _FakeLLM:
    """LLM-Double. Wird im fact-Pfad nicht aufgerufen."""

    def __init__(self):
        self.calls = []

    def complete(self, *a, **k):
        self.calls.append((a, k))
        raise AssertionError("LLM darf im fact-Pfad nicht laufen")


class AskSinceHoursTests(unittest.TestCase):
    """A852: ask(..., since_hours=) reicht an Builder durch."""

    def test_since_hours_wird_durchgereicht(self):
        builder = _FakeBuilder()
        svc = ChatService(
            audit_writer=_FakeAudit(),
            llm_client=_FakeLLM(),
            checker=_FakeChecker(),
            context_builder=builder,
        )
        svc.ask("admin", "Gibt es Auffaelligkeiten?", since_hours=168)
        self.assertEqual(builder.seen_since_hours, 168)

    def test_since_hours_default_24(self):
        builder = _FakeBuilder()
        svc = ChatService(
            audit_writer=_FakeAudit(),
            llm_client=_FakeLLM(),
            checker=_FakeChecker(),
            context_builder=builder,
        )
        svc.ask("admin", "Gibt es Auffaelligkeiten?")
        self.assertEqual(builder.seen_since_hours, 24)


class CategoryLabelsSourceTests(unittest.TestCase):
    """A823: eine Quelle der Wahrheit."""

    def test_labels_wortlaut(self):
        self.assertEqual(CATEGORY_LABELS["EVENT"], "Info")
        self.assertEqual(CATEGORY_LABELS["ANOMALY"], "Hinweis")
        self.assertEqual(CATEGORY_LABELS["SUSPICION"], "Warnung")
        self.assertEqual(CATEGORY_LABELS["SECURITY_ALERT"], "Alarm")
        self.assertEqual(CATEGORY_LABELS["CONFIRMED"], "Kritisch")
