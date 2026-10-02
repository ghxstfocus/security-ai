# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tests fuer die Fehlerklassen-Hierarchie im ChatService (3.6.15c).

Kategorie 3, Auflagen 487-499.

Deckt ab:
- ChatServiceError ist Subklasse von ServiceError (4xx).
- ChatOperationError ist Subklasse von OperationError (5xx).
- ChatOperationError ist NICHT Subklasse von ServiceError.
- ChatOperationError ist NICHT Subklasse von ChatServiceError.
- Konstruktor-None (audit_writer/llm_client/checker) -> ChatOperationError.
- Leere Frage -> ChatServiceError.
"""
from __future__ import annotations

import unittest

from apps.security_ai.chat import (
    ChatOperationError,
    ChatService,
    ChatServiceError,
)
from core.services import OperationError, ServiceError


class _StubAudit:
    def log(self, **kwargs):
        pass


class _StubLLM:
    def generate(self, request):
        raise AssertionError("LLM darf hier nicht gerufen werden")


class _StubChecker:
    def role_of(self, name):
        return None

    def require_permission(self, name, code):
        pass


class ChatErrorHierarchyTests(unittest.TestCase):
    def test_chat_service_error_is_service_error(self):
        self.assertTrue(issubclass(ChatServiceError, ServiceError))

    def test_chat_operation_error_is_operation_error(self):
        self.assertTrue(issubclass(ChatOperationError, OperationError))

    def test_chat_operation_error_is_not_service_error(self):
        self.assertFalse(issubclass(ChatOperationError, ServiceError))

    def test_chat_operation_error_is_not_chat_service_error(self):
        self.assertFalse(
            issubclass(ChatOperationError, ChatServiceError)
        )


class ChatConstructorFailClosedTests(unittest.TestCase):
    def test_none_audit_writer_raises_operation_error(self):
        with self.assertRaises(ChatOperationError):
            ChatService(
                audit_writer=None,
                llm_client=_StubLLM(),
                checker=_StubChecker(),
            )

    def test_none_llm_client_raises_operation_error(self):
        with self.assertRaises(ChatOperationError):
            ChatService(
                audit_writer=_StubAudit(),
                llm_client=None,
                checker=_StubChecker(),
            )

    def test_none_checker_raises_operation_error(self):
        with self.assertRaises(ChatOperationError):
            ChatService(
                audit_writer=_StubAudit(),
                llm_client=_StubLLM(),
                checker=None,
            )


class ChatEmptyQuestionTests(unittest.TestCase):
    def test_empty_question_raises_service_error(self):
        svc = ChatService(
            audit_writer=_StubAudit(),
            llm_client=_StubLLM(),
            checker=_StubChecker(),
        )
        with self.assertRaises(ChatServiceError):
            svc.ask("viewer1", "   ")


if __name__ == "__main__":
    unittest.main()
