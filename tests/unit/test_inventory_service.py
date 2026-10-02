# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tests fuer InventoryService.count_by_network (T3, Auflage 1692).

Kategorie 3 (Kern-Service, RBAC).

Stub-Repos, damit kein DB-Setup und kein
Whitelist-Zugriff noetig ist. Die RBAC-Pruefung
laeuft ueber einen Stub-Checker, der im Erfolgsfall
nichts tut und im Fehlerfall AccessDeniedError wirft.
"""
from __future__ import annotations

import sqlite3
import unittest
from unittest.mock import MagicMock

from core.access.checker import AccessDeniedError
from core.inventory.repository import (
    DeviceRepository,
    apply_migrations,
)
from core.inventory.whitelist import WhitelistRepository
from core.services.inventory_service import (
    InventoryService,
    InventoryServiceError,
)


def _fresh_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    apply_migrations(conn)
    return conn


class _StubDeviceRepo:
    def __init__(self, counts=None):
        self._counts = counts if counts is not None else {
            "Hauptnetz": 3,
            "Gastnetz": 0,
            "Extern": 0,
        }

    def count_by_network(self):
        return dict(self._counts)


class _StubWhitelistRepo:
    pass


class _OkChecker:
    def require_permission(self, actor, code):
        return None


class _DenyChecker:
    def require_permission(self, actor, code):
        raise AccessDeniedError(f"denied: {code}")


class CountByNetworkTests(unittest.TestCase):

    def _service(self, counts=None, checker=None):
        return InventoryService(
            device_repo=_StubDeviceRepo(counts),
            whitelist_repo=_StubWhitelistRepo(),
            checker=checker or _OkChecker(),
        )

    def test_count_by_network_returns_three_keys(self):
        svc = self._service()
        out = svc.count_by_network("admin1")
        self.assertEqual(
            set(out.keys()),
            {"Hauptnetz", "Gastnetz", "Extern"},
        )

    def test_count_by_network_values(self):
        svc = self._service(
            counts={"Hauptnetz": 7, "Gastnetz": 2, "Extern": 1},
        )
        out = svc.count_by_network("admin1")
        self.assertEqual(out["Hauptnetz"], 7)
        self.assertEqual(out["Gastnetz"], 2)
        self.assertEqual(out["Extern"], 1)

    def test_count_by_network_zero_for_missing(self):
        svc = self._service(
            counts={"Hauptnetz": 5, "Gastnetz": 0, "Extern": 0},
        )
        out = svc.count_by_network("admin1")
        self.assertEqual(out["Gastnetz"], 0)
        self.assertEqual(out["Extern"], 0)

    def test_count_by_network_rbac_denied(self):
        svc = self._service(checker=_DenyChecker())
        with self.assertRaises(AccessDeniedError):
            svc.count_by_network("viewer-no-perm")


if __name__ == "__main__":
    unittest.main()


class WhitelistServiceTests(unittest.TestCase):
    """Punkt 56a: add_to_whitelist / remove_from_whitelist."""

    def setUp(self):
        self.conn = _fresh_conn()
        self.device_repo = DeviceRepository(self.conn)
        self.whitelist_repo = WhitelistRepository(self.conn)
        self.checker = MagicMock()
        self.checker.require_permission = MagicMock(return_value=None)
        self.audit = MagicMock()
        self.service = InventoryService(
            device_repo=self.device_repo,
            whitelist_repo=self.whitelist_repo,
            checker=self.checker,
            audit_writer=self.audit,
        )

    def _deny(self):
        self.checker.require_permission = MagicMock(
            side_effect=AccessDeniedError("denied")
        )

    def test_add_to_whitelist_rbac_denied(self):
        self._deny()
        with self.assertRaises(AccessDeniedError):
            self.service.add_to_whitelist("viewer1", "aa:01")

    def test_add_to_whitelist_ok(self):
        out = self.service.add_to_whitelist("admin1", "aa:01")
        self.assertEqual(out["identifier"], "aa:01")

    def test_add_idempotent(self):
        self.service.add_to_whitelist("admin1", "aa:01")
        self.service.add_to_whitelist("admin1", "aa:01")
        self.assertEqual(self.whitelist_repo.count(), 1)

    def test_remove_from_whitelist_ok(self):
        self.service.add_to_whitelist("admin1", "aa:02")
        out = self.service.remove_from_whitelist("admin1", "aa:02")
        self.assertTrue(out["removed"])
        self.assertEqual(self.whitelist_repo.count(), 0)

    def test_remove_unknown_kein_error(self):
        out = self.service.remove_from_whitelist("admin1", "aa:99")
        self.assertFalse(out["removed"])

    def test_audit_called_on_add(self):
        self.service.add_to_whitelist("admin1", "aa:03")
        self.audit.log.assert_called()
        kinds = [
            c.kwargs.get("details", {}).get("kind")
            for c in self.audit.log.call_args_list
        ]
        self.assertIn("whitelist_added", kinds)

    def test_audit_called_on_remove(self):
        self.service.add_to_whitelist("admin1", "aa:04")
        self.audit.log.reset_mock()
        self.service.remove_from_whitelist("admin1", "aa:04")
        self.audit.log.assert_called()
        kinds = [
            c.kwargs.get("details", {}).get("kind")
            for c in self.audit.log.call_args_list
        ]
        self.assertIn("whitelist_removed", kinds)


if __name__ == "__main__":
    unittest.main()


class SetInternalNameTests(unittest.TestCase):
    """Punkt 75: set_internal_name."""

    def setUp(self):
        self.conn = _fresh_conn()
        self.device_repo = DeviceRepository(self.conn)
        self.whitelist_repo = WhitelistRepository(self.conn)
        self.checker = MagicMock()
        self.checker.require_permission = MagicMock(return_value=None)
        self.audit = MagicMock()
        self.service = InventoryService(
            device_repo=self.device_repo,
            whitelist_repo=self.whitelist_repo,
            checker=self.checker,
            audit_writer=self.audit,
        )

    def test_set_internal_name_rbac_denied(self):
        self.checker.require_permission = MagicMock(
            side_effect=AccessDeniedError("denied")
        )
        with self.assertRaises(AccessDeniedError):
            self.service.set_internal_name("viewer1", "aa:01", "Name")

    def test_set_internal_name_ok(self):
        self.device_repo.upsert_seen("aa:01")
        out = self.service.set_internal_name(
            "admin1", "aa:01", "Server-Sandra",
        )
        self.assertEqual(out["internal_name"], "Server-Sandra")

    def test_set_internal_name_too_long(self):
        self.device_repo.upsert_seen("aa:02")
        with self.assertRaises(InventoryServiceError):
            self.service.set_internal_name("admin1", "aa:02", "x" * 81)

    def test_set_internal_name_empty_to_none(self):
        self.device_repo.upsert_seen("aa:03")
        self.service.set_internal_name("admin1", "aa:03", "Erst")
        out = self.service.set_internal_name("admin1", "aa:03", "   ")
        self.assertIsNone(out["internal_name"])

    def test_set_internal_name_audit_called(self):
        self.device_repo.upsert_seen("aa:04")
        self.service.set_internal_name("admin1", "aa:04", "Kamera")
        self.audit.log.assert_called()
        kinds = [
            c.kwargs.get("details", {}).get("kind")
            for c in self.audit.log.call_args_list
        ]
        self.assertIn("internal_name_set", kinds)


if __name__ == "__main__":
    unittest.main()
