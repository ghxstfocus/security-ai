"""
Tests fuer die Fehlerklassen-Hierarchie im InventoryService (3.6.15c).

Kategorie 3, Auflagen 487/491/499 analog.

Deckt ab:
- InventoryServiceError ist Subklasse von ServiceError (4xx).
- InventoryOperationError ist Subklasse von OperationError (5xx).
- InventoryOperationError ist NICHT Subklasse von ServiceError.
- InventoryOperationError ist NICHT Subklasse von
  InventoryServiceError.
- Konstruktor-None -> InventoryOperationError.
- Format-Identifier -> InventoryServiceError.
"""
from __future__ import annotations

import unittest

from core.services import OperationError, ServiceError
from core.services.inventory_service import (
    InventoryOperationError,
    InventoryService,
    InventoryServiceError,
)


class _StubDeviceRepo:
    pass


class _StubWhitelistRepo:
    pass


class _StubChecker:
    def require_permission(self, name, code):
        pass


class InventoryErrorHierarchyTests(unittest.TestCase):
    def test_service_error_is_service_error(self):
        self.assertTrue(
            issubclass(InventoryServiceError, ServiceError)
        )

    def test_operation_error_is_operation_error(self):
        self.assertTrue(
            issubclass(InventoryOperationError, OperationError)
        )

    def test_operation_error_is_not_service_error(self):
        self.assertFalse(
            issubclass(InventoryOperationError, ServiceError)
        )

    def test_operation_error_is_not_inventory_service_error(self):
        self.assertFalse(
            issubclass(InventoryOperationError, InventoryServiceError)
        )


class InventoryConstructorFailClosedTests(unittest.TestCase):
    def test_none_device_repo_raises_operation_error(self):
        with self.assertRaises(InventoryOperationError):
            InventoryService(
                device_repo=None,
                whitelist_repo=_StubWhitelistRepo(),
                checker=_StubChecker(),
            )

    def test_none_whitelist_repo_raises_operation_error(self):
        with self.assertRaises(InventoryOperationError):
            InventoryService(
                device_repo=_StubDeviceRepo(),
                whitelist_repo=None,
                checker=_StubChecker(),
            )

    def test_none_checker_raises_operation_error(self):
        with self.assertRaises(InventoryOperationError):
            InventoryService(
                device_repo=_StubDeviceRepo(),
                whitelist_repo=_StubWhitelistRepo(),
                checker=None,
            )


class InventoryFormatTests(unittest.TestCase):
    def test_non_string_identifier_raises_service_error(self):
        svc = InventoryService(
            device_repo=_StubDeviceRepo(),
            whitelist_repo=_StubWhitelistRepo(),
            checker=_StubChecker(),
        )
        with self.assertRaises(InventoryServiceError):
            svc.get_device("viewer1", None)


if __name__ == "__main__":
    unittest.main()
