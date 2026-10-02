# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tests fuer die Fehlerklassen-Hierarchie im AuditReaderService (3.6.15c).

Kategorie 3, Auflagen 487/499/502-506 analog.

Deckt ab:
- AuditReaderServiceError ist Subklasse von ServiceError (4xx).
- AuditReaderOperationError ist Subklasse von OperationError (5xx).
- AuditReaderOperationError ist NICHT Subklasse von ServiceError.
- AuditReaderOperationError ist NICHT Subklasse von
  AuditReaderServiceError.
- Konstruktor-None -> AuditReaderOperationError.
- Format-Datum -> AuditReaderServiceError.
"""
from __future__ import annotations

import unittest

from core.services import OperationError, ServiceError
from core.services.audit_reader_service import (
    AuditReaderOperationError,
    AuditReaderService,
    AuditReaderServiceError,
)


class _StubAudit:
    base_dir = None

    def read_day(self, when):
        return []


class _StubChecker:
    def require_permission(self, name, code):
        pass


class AuditReaderErrorHierarchyTests(unittest.TestCase):
    def test_service_error_is_service_error(self):
        self.assertTrue(
            issubclass(AuditReaderServiceError, ServiceError)
        )

    def test_operation_error_is_operation_error(self):
        self.assertTrue(
            issubclass(AuditReaderOperationError, OperationError)
        )

    def test_operation_error_is_not_service_error(self):
        self.assertFalse(
            issubclass(AuditReaderOperationError, ServiceError)
        )

    def test_operation_error_is_not_audit_reader_service_error(self):
        self.assertFalse(
            issubclass(
                AuditReaderOperationError, AuditReaderServiceError,
            )
        )


class AuditReaderConstructorFailClosedTests(unittest.TestCase):
    def test_none_audit_writer_raises_operation_error(self):
        with self.assertRaises(AuditReaderOperationError):
            AuditReaderService(
                audit_writer=None,
                checker=_StubChecker(),
            )

    def test_none_checker_raises_operation_error(self):
        with self.assertRaises(AuditReaderOperationError):
            AuditReaderService(
                audit_writer=_StubAudit(),
                checker=None,
            )


class AuditReaderFormatTests(unittest.TestCase):
    def test_invalid_date_raises_service_error(self):
        svc = AuditReaderService(
            audit_writer=_StubAudit(),
            checker=_StubChecker(),
        )
        with self.assertRaises(AuditReaderServiceError):
            svc.read_day("viewer1", "not-a-date")


if __name__ == "__main__":
    unittest.main()
