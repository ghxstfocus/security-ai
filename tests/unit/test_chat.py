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
from datetime import datetime, timezone
from pathlib import Path

from apps.security_ai.chat import (
    ChatService,
    ChatServiceError,
    ChatResponse,
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
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
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
        r = self.svc.ask("admin", "Was ist passiert?")
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
        with self.assertRaises(ChatServiceError):
            ChatService(self.conn, None, self.llm)
        with self.assertRaises(ChatServiceError):
            ChatService(self.conn, self.audit, None)

    def test_system_prompt_verbietet_spekulation(self):
        from apps.security_ai.chat import _DEFAULT_SYSTEM_PROMPT
        sp = _DEFAULT_SYSTEM_PROMPT
        self.assertIn("NUR auf Basis des mitgelieferten Kontexts", sp)
        self.assertIn("Spekuliere nicht", sp)
        self.assertIn("Kontext enthaelt keine passenden Daten", sp)


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

    def test_include_details_wird_nicht_geloggt_wenn_nicht_gesetzt(self):
        self.svc.ask("admin", "Frage?")
        entry = [
            e for e in self._audit_entries()
            if e["details"]["kind"] == "chat_query"
        ][0]
        self.assertFalse(entry["details"]["detail_requested"])
        self.assertNotIn("question", entry["details"])


if __name__ == "__main__":
    unittest.main()
