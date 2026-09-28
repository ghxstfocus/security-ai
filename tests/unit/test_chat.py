"""
Tests fuer apps/security_ai/chat.py (ChatService).

FakeLLM statt echtem Ollama. Kein Netz.
Deckt RBAC, Detail-Pfad, Modellwahl, Fail-closed bei LLM,
Audit-Kinds und question_hash ab.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timezone
from pathlib import Path

from apps.security_ai.chat import (
    ChatOperationError,
    ChatResponse,
    ChatService,
    ChatServiceError,
)
from core.access.checker import AccessChecker, AccessDeniedError
from core.access.models import PrincipalKind
from core.access.repository import (
    PermissionRepository,
    PrincipalRepository,
    RoleRepository,
)
from core.inventory.repository import apply_migrations
from harness.audit.writer import AuditWriter
from harness.context.models import LogExcerpt
from harness.llm.errors import LLMError, LLMUnavailable
from harness.llm.models import LLMRequest, LLMResponse

# ---------------------------------------------------------------------- #
# Fake-LLM
# ---------------------------------------------------------------------- #

class FakeLLM:
    """
    Protocol-konform: generate(request: LLMRequest) -> LLMResponse.
    Zaehlt Aufrufe, optional mit Fehler.
    """

    def __init__(self, text: str = "Antwort.", error=None) -> None:
        self.text = text
        self.error = error
        self.calls: list[LLMRequest] = []

    def generate(self, request: LLMRequest) -> LLMResponse:
        self.calls.append(request)
        if self.error is not None:
            raise self.error
        return LLMResponse(text=self.text, model=request.model)


# ---------------------------------------------------------------------- #
# Basis-Setup
# ---------------------------------------------------------------------- #

class _ChatBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.conn = sqlite3.connect(self.tmp / "inv.db")
        apply_migrations(self.conn, "data/migrations")

        roles = RoleRepository(self.conn)
        self.role_admin = roles.get_by_name("admin")
        self.role_viewer = roles.get_by_name("viewer")
        pr = PrincipalRepository(self.conn)
        pr.create(name="admin", role_id=self.role_admin.row_id,
                  kind=PrincipalKind.HUMAN)
        pr.create(name="viewer1", role_id=self.role_viewer.row_id,
                  kind=PrincipalKind.HUMAN)

        self.audit_dir = self.tmp / "audit-logs"
        self.audit = AuditWriter(base_dir=self.audit_dir)
        self.llm = FakeLLM(text="Antwort.")

        self.checker = AccessChecker(
            PrincipalRepository(self.conn),
            RoleRepository(self.conn),
            PermissionRepository(self.conn),
        )
        self.svc = ChatService(
            audit_writer=self.audit,
            llm_client=self.llm,
            checker=self.checker,
            default_model="llama3.2:3b",
        )

    def tearDown(self) -> None:
        self.conn.close()
        self._tmp.cleanup()

    # ------------------------------------------------------------------ #
    # Helfer
    # ------------------------------------------------------------------ #

    def _audit_entries(self) -> list[dict]:
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        f = self.audit_dir / f"{today}.jsonl"
        if not f.exists():
            return []
        return [
            json.loads(line)
            for line in f.read_text().splitlines() if line.strip()
        ]

    def _kinds(self) -> list[str]:
        return [e["details"]["kind"] for e in self._audit_entries()]


# ---------------------------------------------------------------------- #
# Happy Path / Modellwahl
# ---------------------------------------------------------------------- #

class ChatServiceHappyPathTests(_ChatBase):
    def test_llm_pfad(self):
        # Konzeptfrage, kein Kontext noetig -> LLM-Pfad
        r = self.svc.ask("admin", "Was ist ein Portscan?")
        self.assertIsInstance(r, ChatResponse)
        self.assertEqual(r.answer, "Antwort.")
        self.assertEqual(r.source, "llm")
        self.assertEqual(r.model, "llama3.2:3b")
        self.assertTrue(r.used_llm)
        self.assertFalse(r.denied)
        self.assertEqual(len(self.llm.calls), 1)
        self.assertEqual(self.llm.calls[0].model, "llama3.2:3b")

    def test_model_override(self):
        r = self.svc.ask("admin", "Frage?", model="qwen2.5:7b")
        self.assertEqual(r.model, "qwen2.5:7b")
        self.assertEqual(self.llm.calls[-1].model, "qwen2.5:7b")

    def test_leere_frage_wirft(self):
        for bad in ("", "   ", None, 123):
            with self.assertRaises(ChatServiceError, msg=bad):
                self.svc.ask("admin", bad)

    def test_konstruktor_fail_closed(self):
        # Auflage 487: Konstruktor-None ist Betriebsfehler (5xx).
        with self.assertRaises(ChatOperationError):
            ChatService(self.conn, None, self.llm)
        with self.assertRaises(ChatOperationError):
            ChatService(self.conn, self.audit, None)

    def test_system_prompt_unterscheidet_konzept_und_zustand(self):
        from apps.security_ai.chat import _DEFAULT_SYSTEM_PROMPT
        sp = _DEFAULT_SYSTEM_PROMPT
        # Konzeptfragen
        self.assertIn("Konzeptfragen", sp)
        self.assertIn("aus deinem", sp)
        # Zustandsfragen
        self.assertIn("Zustandsfragen", sp)
        self.assertIn("NUR auf Basis des mitgelieferten Kontexts", sp)
        # Ehrlichkeit statt Spekulation
        self.assertIn("sage das ehrlich", sp)
        self.assertIn("Spekuliere nicht", sp)

    def test_system_prompt_verbietet_entscheidungen(self):
        from apps.security_ai.chat import _DEFAULT_SYSTEM_PROMPT
        sp = _DEFAULT_SYSTEM_PROMPT
        self.assertIn("Du entscheidest nicht", sp)
        self.assertIn("Du erklaerst", sp)
        self.assertIn("ohne Freigabe", sp)


# ---------------------------------------------------------------------- #
# RBAC
# ---------------------------------------------------------------------- #

class ChatServiceRbacTests(_ChatBase):
    def test_chat_ask_fehlt(self):
        # viewer hat chat.ask. Wir bauen einen Principal ohne chat.ask:
        # inaktiv machen reicht (has_permission -> False).
        pr = PrincipalRepository(self.conn)
        pr.set_active("viewer1", False)
        with self.assertRaises(AccessDeniedError):
            self.svc.ask("viewer1", "Frage?")
        kinds = self._kinds()
        self.assertIn("chat_query", kinds)
        self.assertIn("chat_access_denied", kinds)

    def test_chat_include_details_fehlt(self):
        with self.assertRaises(AccessDeniedError):
            self.svc.ask("viewer1", "Frage?", include_details=True)
        denied = [
            e for e in self._audit_entries()
            if e["details"]["kind"] == "chat_access_denied"
        ]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["details"]["reason"],
                         "missing chat.include_details")

    def test_unbekannter_principal(self):
        with self.assertRaises(AccessDeniedError):
            self.svc.ask("gibtsnicht", "Frage?")
        # chat_query steht trotzdem im Audit
        self.assertIn("chat_query", self._kinds())


# ---------------------------------------------------------------------- #
# Detail-Pfad
# ---------------------------------------------------------------------- #

class ChatServiceDetailTests(_ChatBase):
    def test_detail_regex_mit_recht(self):
        self.llm.calls.clear()
        r = self.svc.ask("admin", "welche IP ist neu?",
                         inventory_snapshot={
                             "recently_added": ["192.168.178.1",
                                                "192.168.178.2"],
                         })
        self.assertEqual(r.source, "detail_append")
        self.assertFalse(r.used_llm)
        self.assertEqual(r.model, None)
        self.assertIn("192.168.178.1", r.answer)
        self.assertIn("192.168.178.2", r.answer)
        self.assertEqual(self.llm.calls, [])

    def test_detail_parameter_mit_recht(self):
        self.llm.calls.clear()
        r = self.svc.ask("admin", "irgendeine Frage", detail=True)
        self.assertEqual(r.source, "detail_append")
        self.assertEqual(self.llm.calls, [])

    def test_detail_regex_ohne_recht(self):
        with self.assertRaises(AccessDeniedError):
            self.svc.ask("viewer1", "welche IP?")
        denied = [
            e for e in self._audit_entries()
            if e["details"]["kind"] == "chat_access_denied"
        ]
        self.assertEqual(denied[0]["details"]["reason"],
                         "missing chat.detail")

    def test_detail_keine_daten(self):
        r = self.svc.ask("admin", "welche IP?", detail=True)
        self.assertIn("(keine Details verfuegbar)", r.answer)

    def test_detail_aus_event(self):
        class FakeEvent:
            data = {"identifier": "10.0.0.5"}
        r = self.svc.ask("admin", "welche IP?", detail=True,
                         event=FakeEvent())
        self.assertIn("10.0.0.5", r.answer)

    def test_detail_dedupliziert(self):
        r = self.svc.ask(
            "admin", "welche IP?", detail=True,
            inventory_snapshot={
                "recently_added": ["10.0.0.1"],
                "recently_offline": ["10.0.0.1", "10.0.0.2"],
            },
        )
        self.assertEqual(r.answer.count("10.0.0.1"), 1)
        self.assertEqual(r.answer.count("10.0.0.2"), 1)


# ---------------------------------------------------------------------- #
# Prompt / include_details
# ---------------------------------------------------------------------- #

class ChatServicePromptTests(_ChatBase):
    def test_include_details_logs_im_prompt(self):
        self.svc.ask(
            "admin", "Was steht im Log?",
            include_details=True,
            log_excerpts=(
                LogExcerpt(path="/var/log/syslog",
                           text="zeile1", line_count=1),
            ),
        )
        prompt = self.llm.calls[-1].prompt
        self.assertIn("log[0] /var/log/syslog: zeile1", prompt)

    def test_ohne_include_details_keine_logs(self):
        self.svc.ask(
            "admin", "Was?",
            log_excerpts=(
                LogExcerpt(path="/var/log/syslog",
                           text="zeile1", line_count=1),
            ),
        )
        prompt = self.llm.calls[-1].prompt
        self.assertNotIn("log[0]", prompt)


# ---------------------------------------------------------------------- #
# LLM-Fehler (fail closed)
# ---------------------------------------------------------------------- #

class ChatServiceLlmErrorTests(_ChatBase):
    def test_llmerror_wird_propagiert(self):
        llm = FakeLLM(error=LLMUnavailable("ollama down"))
        svc = ChatService(audit_writer=self.audit, llm_client=llm, checker=self.checker,
                          default_model="llama3.2:3b")
        with self.assertRaises(LLMError):
            svc.ask("admin", "Frage?")
        kinds = self._kinds()
        self.assertIn("chat_llm_error", kinds)
        # keine chat_answered bei Fehler
        self.assertNotIn("chat_answered", kinds)

    def test_client_ohne_text_feld_wirft(self):
        class KaputtLLM:
            def generate(self, request):
                return object()
        svc = ChatService(audit_writer=self.audit, llm_client=KaputtLLM(), checker=self.checker)
        with self.assertRaises(ChatServiceError):
            svc.ask("admin", "Frage?")
        kinds = self._kinds()
        self.assertIn("chat_llm_error", kinds)


# ---------------------------------------------------------------------- #
# Audit-Details
# ---------------------------------------------------------------------- #

class ChatServiceAuditTests(_ChatBase):
    def test_chat_query_immer_zuerst(self):
        self.svc.ask("admin", "Frage?")
        kinds = self._kinds()
        self.assertEqual(kinds[0], "chat_query")

    def test_question_hash(self):
        q = "Was ist passiert?"
        self.svc.ask("admin", q)
        entry = [
            e for e in self._audit_entries()
            if e["details"]["kind"] == "chat_query"
        ][0]
        expected = hashlib.sha256(q.encode("utf-8")).hexdigest()
        self.assertEqual(entry["details"]["question_hash"], expected)
        self.assertEqual(
            entry["details"]["question_hash_short"], expected[:16]
        )

    def test_chat_query_enthaelt_role(self):
        self.svc.ask("admin", "Frage?")
        entry = [
            e for e in self._audit_entries()
            if e["details"]["kind"] == "chat_query"
        ][0]
        self.assertEqual(entry["details"]["role"], "admin")

    def test_chat_query_role_none_bei_unbekannt(self):
        try:
            self.svc.ask("gibtsnicht", "Frage?")
        except AccessDeniedError:
            pass
        entry = [
            e for e in self._audit_entries()
            if e["details"]["kind"] == "chat_query"
        ][0]
        self.assertIsNone(entry["details"]["role"])

    def test_chat_query_enthaelt_detail_requested(self):
        self.svc.ask("admin", "Frage?", detail=True)
        entry = [
            e for e in self._audit_entries()
            if e["details"]["kind"] == "chat_query"
        ][0]
        self.assertTrue(entry["details"]["detail_requested"])

    def test_chat_answered_source_llm(self):
        self.svc.ask("admin", "Frage?")
        answered = [
            e for e in self._audit_entries()
            if e["details"]["kind"] == "chat_answered"
        ][0]
        self.assertEqual(answered["details"]["source"], "llm")
        self.assertEqual(answered["details"]["model"], "llama3.2:3b")

    def test_chat_answered_source_detail(self):
        self.svc.ask("admin", "welche IP?", detail=True)
        answered = [
            e for e in self._audit_entries()
            if e["details"]["kind"] == "chat_answered"
        ][0]
        self.assertEqual(answered["details"]["source"], "detail_append")

    def test_chat_answered_detail_has_model_reason(self):
        # Punkt 23: model_reason muss auch im Audit stehen.
        self.svc.ask("admin", "welche IP?", detail=True)
        answered = [
            e for e in self._audit_entries()
            if e["details"]["kind"] == "chat_answered"
        ][0]
        self.assertEqual(
            answered["details"].get("model_reason"),
            "detail_append",
        )

    def test_chat_answered_fact_has_model_reason(self):
        # Punkt 23: fact-Pfad muss model_reason="fact" setzen.
        from harness.context.models import utc_now
        self.svc.ask(
            "admin", "Wie viele Events gab es?",
            risk_assessments=(),
            inventory_snapshot={"devices_total": 3},
        )
        answered = [
            e for e in self._audit_entries()
            if e["details"]["kind"] == "chat_answered"
        ][0]
        self.assertEqual(
            answered["details"].get("model_reason"),
            "fact",
        )

    def test_chat_answered_no_context_has_model_reason(self):
        # Punkt 23: no_context-Pfad muss model_reason setzen.
        # Zustandsfrage ohne Kontext -> no_context.
        self.svc.ask("admin", "Welche IPs sind online?")
        answered = [
            e for e in self._audit_entries()
            if e["details"]["kind"] == "chat_answered"
        ][0]
        self.assertIn(
            answered["details"].get("source"),
            ("no_context", "llm"),
        )
        # Wenn no_context: model_reason gesetzt.
        if answered["details"].get("source") == "no_context":
            self.assertEqual(
                answered["details"].get("model_reason"),
                "no_context",
            )

    def test_include_details_wird_nicht_geloggt_wenn_nicht_gesetzt(self):
        self.svc.ask("admin", "Frage?")
        entry = [
            e for e in self._audit_entries()
            if e["details"]["kind"] == "chat_query"
        ][0]
        self.assertFalse(entry["details"]["detail_requested"])
        self.assertNotIn("question", entry["details"])


# ---------------------------------------------------------------------- #
# no_context-Pfad
# ---------------------------------------------------------------------- #

class ChatServiceNoContextTests(_ChatBase):
    def test_faktfrage_leerer_kontext_kein_llm(self):
        # "Gab es Auffaelligkeiten?" ist fact -> kein LLM.
        self.llm.calls.clear()
        r = self.svc.ask(
            "admin", "Gab es heute Nacht Auffaelligkeiten?"
        )
        self.assertEqual(r.source, "fact")
        self.assertFalse(r.used_llm)
        self.assertEqual(r.model, None)
        self.assertIn("keine", r.answer.lower())
        self.assertEqual(self.llm.calls, [])

    def test_faktfrage_mit_kontext_deterministisch(self):
        self.llm.calls.clear()
        r = self.svc.ask(
            "admin", "Gab es Auffaelligkeiten?",
            risk_assessments=(
                {"category": "CONFIRMED", "score": 0.85},
            ),
        )
        self.assertEqual(r.source, "fact")
        self.assertFalse(r.used_llm)
        self.assertIn("JA", r.answer)
        # Punkt 31 (A821/A824): Anzeige-Label statt Rohkategorie.
        self.assertIn("Kritisch=1", r.answer)
        # A825: "Assessments" -> "Vorkommen".
        self.assertIn("Vorkommen", r.answer)
        # A839: Zeitraum aus since_hours (Default 24).
        self.assertIn("in den letzten 24 Stunden", r.answer)
        self.assertEqual(self.llm.calls, [])

    def test_konzeptfrage_leerer_kontext_llm_pfad(self):
        self.llm.calls.clear()
        r = self.svc.ask("admin", "Was ist ein Portscan?")
        self.assertEqual(r.source, "llm")
        self.assertTrue(r.used_llm)
        self.assertEqual(len(self.llm.calls), 1)

    def test_interpretation_leerer_kontext_no_context(self):
        # Interpretation + vage Zustandsfrage + kein Kontext
        # -> no_context
        self.llm.calls.clear()
        r = self.svc.ask("admin", "Warum ist das verdaechtig?")
        self.assertEqual(r.source, "no_context")
        self.assertFalse(r.used_llm)
        self.assertIn("keine daten", r.answer.lower())
        self.assertEqual(self.llm.calls, [])

    def test_no_context_audit_eintrag(self):
        self.svc.ask("admin", "Warum ist das verdaechtig?")
        answered = [
            e for e in self._audit_entries()
            if e["details"]["kind"] == "chat_answered"
        ]
        self.assertEqual(len(answered), 1)
        self.assertEqual(answered[0]["details"]["source"], "no_context")


# ---------------------------------------------------------------------- #
# Prompt-Anreicherung fuer risk_assessments
# ---------------------------------------------------------------------- #

class ChatServicePromptEnrichmentTests(_ChatBase):
    def test_prompt_enthaelt_categories_rules_top_scores(self):
        self.svc.ask(
            "admin", "Was ist ein Portscan?",  # Konzeptfrage -> LLM-Pfad
            risk_assessments=(
                {"category": "CONFIRMED", "rule_id": "unknown_device",
                 "score": 0.85,
                 "timestamp": "2026-09-22T06:00:00+00:00"},
                {"category": "SUSPICION", "rule_id": "port_scan",
                 "score": 0.5,
                 "timestamp": "2026-09-22T06:30:00+00:00"},
            ),
        )
        prompt = self.llm.calls[-1].prompt
        self.assertIn("risk_assessments.categories", prompt)
        self.assertIn("CONFIRMED=1", prompt)
        self.assertIn("SUSPICION=1", prompt)
        self.assertIn("risk_assessments.rules", prompt)
        self.assertIn("port_scan=1", prompt)
        self.assertIn("risk_assessments.top_scores", prompt)
        self.assertIn("0.85", prompt)
        self.assertIn("risk_assessments.time_range", prompt)

    def test_prompt_ohne_risk_assessments_kein_zusatzblock(self):
        self.svc.ask("admin", "Was ist ein Portscan?")
        prompt = self.llm.calls[-1].prompt
        self.assertNotIn("risk_assessments.categories", prompt)
        self.assertNotIn("risk_assessments.rules", prompt)
        self.assertNotIn("risk_assessments.top_scores", prompt)

    def test_prompt_mit_objekt_form(self):
        class RA:
            def __init__(self, cat, rule, score, ts):
                self.category = cat
                self.rule_id = rule
                self.score = score
                self.timestamp = ts

        self.svc.ask(
            "admin", "Was ist ein Portscan?",
            risk_assessments=(
                RA("SECURITY_ALERT", "port_scan", 0.9,
                   "2026-09-22T07:00:00+00:00"),
            ),
        )
        prompt = self.llm.calls[-1].prompt
        self.assertIn("SECURITY_ALERT=1", prompt)
        self.assertIn("port_scan=1", prompt)
        self.assertIn("0.90", prompt)


# ---------------------------------------------------------------------- #
# Auto-Switch + Timeouts
# ---------------------------------------------------------------------- #

class ChatServiceAutoSwitchTests(_ChatBase):
    # Auto-Switch greift nur bei Interpretationsfragen (nicht
    # fact, nicht concept).
    _FRAGE = "Warum ist das verdaechtig?"

    def test_auto_switch_bei_confirmed(self):
        self.llm.calls.clear()
        r = self.svc.ask(
            "admin", self._FRAGE,
            risk_assessments=(
                {"category": "CONFIRMED", "score": 0.85},
            ),
        )
        self.assertEqual(r.model, "qwen2.5:7b")
        self.assertEqual(r.model_reason, "auto_critical_state")
        self.assertEqual(self.llm.calls[-1].model, "qwen2.5:7b")
        self.assertEqual(self.llm.calls[-1].timeout, 180.0)

    def test_auto_switch_bei_security_alert(self):
        self.llm.calls.clear()
        r = self.svc.ask(
            "admin", self._FRAGE,
            risk_assessments=(
                {"category": "SECURITY_ALERT", "score": 0.6},
            ),
        )
        self.assertEqual(r.model, "qwen2.5:7b")
        self.assertEqual(r.model_reason, "auto_critical_state")

    def test_kein_auto_switch_bei_event_only(self):
        self.llm.calls.clear()
        r = self.svc.ask(
            "admin", self._FRAGE,
            risk_assessments=(
                {"category": "EVENT", "score": 0.1},
            ),
        )
        self.assertEqual(r.model, "llama3.2:3b")
        self.assertEqual(r.model_reason, "default")
        self.assertEqual(self.llm.calls[-1].timeout, 30.0)

    def test_kein_auto_switch_bei_konzeptfrage(self):
        self.llm.calls.clear()
        r = self.svc.ask(
            "admin", "Was ist ein Portscan?",
            risk_assessments=(
                {"category": "CONFIRMED", "score": 0.85},
            ),
        )
        self.assertEqual(r.model, "llama3.2:3b")
        self.assertEqual(r.model_reason, "concept")

    def test_explicit_model_gewinnt(self):
        self.llm.calls.clear()
        r = self.svc.ask(
            "admin", self._FRAGE,
            model="qwen2.5:7b",
            risk_assessments=(
                {"category": "CONFIRMED", "score": 0.85},
            ),
        )
        self.assertEqual(r.model, "qwen2.5:7b")
        self.assertEqual(r.model_reason, "explicit_user")

    def test_auto_large_false_deaktiviert(self):
        svc = ChatService(
            audit_writer=self.audit,
            llm_client=self.llm,
            checker=self.checker,
            auto_large=False,
            default_model="llama3.2:3b",
            large_model="qwen2.5:7b",
        )
        self.llm.calls.clear()
        r = svc.ask(
            "admin", self._FRAGE,
            risk_assessments=(
                {"category": "CONFIRMED", "score": 0.85},
            ),
        )
        # auto_large=False -> erster Aufruf 3B
        self.assertEqual(self.llm.calls[0].model, "llama3.2:3b")
        # Aber: Antwort nennt kein CONFIRMED -> Sanity-Check
        # greift -> Retry mit 7B. Der Sanity-Check ist nicht
        # durch auto_large abschaltbar (Sicherheitsschicht).
        self.assertEqual(len(self.llm.calls), 2)
        self.assertEqual(self.llm.calls[1].model, "qwen2.5:7b")
        self.assertEqual(r.model, "qwen2.5:7b")
        self.assertEqual(r.source, "llm_retry")
        self.assertEqual(r.model_reason, "auto_retry_contradiction")
        # (Retry kann source auf "llm_retry" aendern, wenn die
        # Antwort kein CONFIRMED nennt. Wir pruefen hier nur
        # model + model_reason.)


class TimeoutHelperTests(unittest.TestCase):
    def test_bekannte_modelle(self):
        from apps.security_ai.chat import _timeout_for_model
        self.assertEqual(_timeout_for_model("llama3.2:3b"), 30)
        self.assertEqual(_timeout_for_model("qwen2.5:7b"), 180)

    def test_unbekanntes_modell(self):
        from apps.security_ai.chat import _timeout_for_model
        self.assertEqual(_timeout_for_model("unbekannt:1b"), 60)

    def test_leerer_string(self):
        from apps.security_ai.chat import _timeout_for_model
        self.assertEqual(_timeout_for_model(""), 60)
        self.assertEqual(_timeout_for_model(None), 60)


# ---------------------------------------------------------------------- #
# on_model_selected-Callback (Phase 3.5.7b)
# ---------------------------------------------------------------------- #

class ChatServiceModelCallbackTests(_ChatBase):
    def test_callback_wird_vor_llm_aufruf_gerufen(self):
        calls: list[tuple[str, str]] = []

        def cb(model, reason):
            calls.append((model, reason))
            # LLM darf noch nicht gerufen worden sein
            self.assertEqual(self.llm.calls, [])

        self.llm.calls.clear()
        self.svc.ask(
            "admin", "Was ist ein Portscan?",
            on_model_selected=cb,
        )
        self.assertEqual(len(calls), 1)
        # "Was ist ein Portscan?" ist concept -> 3B
        self.assertEqual(calls[0], ("llama3.2:3b", "concept"))
        # LLM wurde danach gerufen
        self.assertEqual(len(self.llm.calls), 1)

    def test_callback_mit_auto_switch(self):
        calls: list[tuple[str, str]] = []

        def cb(model, reason):
            calls.append((model, reason))

        # Interpretationsfrage + CONFIRMED -> 7B
        self.svc.ask(
            "admin", "Warum ist das verdaechtig?",
            on_model_selected=cb,
            risk_assessments=(
                {"category": "CONFIRMED", "score": 0.85},
            ),
        )
        self.assertEqual(calls[0], ("qwen2.5:7b", "auto_critical_state"))

    def test_callback_fehler_wird_nicht_propagiert(self):
        def bad_cb(model, reason):
            raise RuntimeError("boom")

        # kein raise nach aussen
        r = self.svc.ask(
            "admin", "Was ist ein Portscan?",
            on_model_selected=bad_cb,
        )
        self.assertEqual(r.source, "llm")
        kinds = [e["details"]["kind"] for e in self._audit_entries()]
        self.assertIn("chat_model_callback_failed", kinds)

    def test_callback_ohne_parameter_kein_fehler(self):
        # Standardfall: kein Callback
        r = self.svc.ask("admin", "Was ist ein Portscan?")
        self.assertEqual(r.source, "llm")

    def test_callback_nicht_bei_fact(self):
        # Fact-Pfad ruft kein LLM -> kein Callback.
        calls: list[tuple[str, str]] = []

        def cb(model, reason):
            calls.append((model, reason))

        self.svc.ask(
            "admin", "Gab es Auffaelligkeiten?",
            on_model_selected=cb,
            risk_assessments=(
                {"category": "CONFIRMED", "score": 0.85},
            ),
        )
        self.assertEqual(calls, [])


# ---------------------------------------------------------------------- #
# Sanity-Check + Retry (Phase 3.5.9)
# ---------------------------------------------------------------------- #

class _FailThenPassLLM:
    """Erste Antwort leugnet, zweite Antwort bestaetigt."""
    def __init__(self):
        self.calls = []

    def generate(self, request):
        from harness.llm.models import LLMResponse
        self.calls.append(request)
        if len(self.calls) == 1:
            text = "NEIN, es gab keine Auffaelligkeiten."
        else:
            text = "JA. CONFIRMED=31 und SECURITY_ALERT=12."
        return LLMResponse(text=text, model=request.model)


class ChatServiceSanityRetryTests(_ChatBase):
    def test_answer_contradicts_context_mit_31_confirmed(self):
        from datetime import datetime

        from apps.security_ai.chat import _answer_contradicts_context
        from harness.context.models import ContextBundle
        now = datetime.now(UTC)
        ctx = ContextBundle(
            built_at=now,
            risk_assessments=(
                {"category": "CONFIRMED", "score": 0.85},
                {"category": "CONFIRMED", "score": 0.8},
                {"category": "SECURITY_ALERT", "score": 0.6},
            ),
        )
        self.assertTrue(
            _answer_contradicts_context(
                "NEIN, keine Auffaelligkeiten.", ctx
            )
        )
        self.assertFalse(
            _answer_contradicts_context("JA. CONFIRMED=31.", ctx)
        )

    def test_answer_ok_kein_retry(self):
        # Normale Antwort -> kein Retry
        self.llm.calls.clear()
        r = self.svc.ask(
            "admin", "Warum ist das verdaechtig?",
            risk_assessments=(
                {"category": "CONFIRMED", "score": 0.85},
            ),
        )
        # FakeLLM antwortet "Antwort." -> kein Widerspruch
        self.assertEqual(r.source, "llm")
        self.assertEqual(len(self.llm.calls), 1)

    def test_answer_contradicts_context_retry_mit_grossem(self):
        # Erste Antwort widerspricht -> Retry mit 7B
        fail_then_pass = _FailThenPassLLM()
        svc = ChatService(
            audit_writer=self.audit,
            llm_client=fail_then_pass,
            checker=self.checker,
            default_model="llama3.2:3b",
            large_model="qwen2.5:7b",
            auto_large=False,  # Auto-Switch aus, damit 3B zuerst
        )
        r = svc.ask(
            "admin", "Warum ist das verdaechtig?",
            risk_assessments=(
                {"category": "CONFIRMED", "score": 0.85},
            ),
        )
        # Retry mit 7B
        self.assertEqual(len(fail_then_pass.calls), 2)
        self.assertEqual(fail_then_pass.calls[0].model, "llama3.2:3b")
        self.assertEqual(fail_then_pass.calls[1].model, "qwen2.5:7b")
        # Antwort ist der 7B-Text
        self.assertEqual(r.source, "llm_retry")
        self.assertEqual(r.model, "qwen2.5:7b")
        self.assertEqual(r.model_reason, "auto_retry_contradiction")
        self.assertIn("JA", r.answer)

    def test_answer_contradicts_audit_eintrag(self):
        fail_then_pass = _FailThenPassLLM()
        svc = ChatService(
            audit_writer=self.audit,
            llm_client=fail_then_pass,
            checker=self.checker,
            default_model="llama3.2:3b",
            large_model="qwen2.5:7b",
            auto_large=False,
        )
        svc.ask(
            "admin", "Warum ist das verdaechtig?",
            risk_assessments=(
                {"category": "CONFIRMED", "score": 0.85},
            ),
        )
        kinds = [e["details"]["kind"] for e in self._audit_entries()]
        self.assertIn("chat_answer_contradicts_context", kinds)
        self.assertIn("chat_answered", kinds)

    def test_retry_source_ist_llm_retry(self):
        fail_then_pass = _FailThenPassLLM()
        svc = ChatService(
            audit_writer=self.audit,
            llm_client=fail_then_pass,
            checker=self.checker,
            default_model="llama3.2:3b",
            large_model="qwen2.5:7b",
            auto_large=False,
        )
        r = svc.ask(
            "admin", "Warum ist das verdaechtig?",
            risk_assessments=(
                {"category": "CONFIRMED", "score": 0.85},
            ),
        )
        self.assertEqual(r.source, "llm_retry")
        answered = [
            e for e in self._audit_entries()
            if e["details"]["kind"] == "chat_answered"
        ]
        sources = [e["details"].get("source") for e in answered]
        self.assertIn("llm", sources)
        self.assertIn("llm_retry", sources)


if __name__ == "__main__":
    unittest.main()


class _NavChecker:
    """Checker-Double: alert.view steuerbar."""

    def __init__(self, allow_alert_view):
        self.allow_alert_view = allow_alert_view

    def role_of(self, name):
        return "admin"

    def require_permission(self, name, code):
        return None

    def check(self, name, code):
        if code == "alert.view":
            return self.allow_alert_view
        return True


class _NavAudit:
    def log(self, *a, **k):
        return None


class _NavLLM:
    def complete(self, *a, **k):
        raise AssertionError("LLM darf im fact-Pfad nicht laufen")


class _NavBuilder:
    def build(self, **kwargs):
        from harness.context.models import ContextBundle, utc_now
        ra = kwargs.get("risk_assessments")
        if not ra:
            ra = ({"category": "CONFIRMED", "score": 0.9},)
        return ContextBundle(
            built_at=utc_now(),
            risk_assessments=tuple(ra),
        )


class NavLinksTests(unittest.TestCase):
    """A875: nav_links nur bei auff_ja + alert.view."""

    def _svc(self, allow_alert_view):
        return ChatService(
            audit_writer=_NavAudit(),
            llm_client=_NavLLM(),
            checker=_NavChecker(allow_alert_view),
            context_builder=_NavBuilder(),
        )

    def test_auff_ja_mit_alert_view_setzt_nav_links(self):
        r = self._svc(True).ask(
            "admin", "Gibt es Auffaelligkeiten?",
        )
        self.assertEqual(r.source, "fact")
        self.assertEqual(len(r.nav_links), 1)
        self.assertEqual(r.nav_links[0]["href"], "/alerts")

    def test_auff_ja_ohne_alert_view_leer(self):
        r = self._svc(False).ask(
            "admin", "Gibt es Auffaelligkeiten?",
        )
        self.assertEqual(r.nav_links, [])

    def test_auff_nein_leer(self):
        svc = self._svc(True)
        r = svc.ask(
            "admin", "Gibt es Auffaelligkeiten?",
            risk_assessments=(
                {"category": "SUSPICION", "score": 0.5},
            ),
        )
        self.assertEqual(r.nav_links, [])

    def test_kategorien_zweig_leer(self):
        r = self._svc(True).ask("admin", "Welche Kategorien?")
        self.assertEqual(r.nav_links, [])
