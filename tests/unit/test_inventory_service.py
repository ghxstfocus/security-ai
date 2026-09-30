"""
Tests fuer InventoryService.count_by_network (T3, Auflage 1692).

Kategorie 3 (Kern-Service, RBAC).

Stub-Repos, damit kein DB-Setup und kein
Whitelist-Zugriff noetig ist. Die RBAC-Pruefung
laeuft ueber einen Stub-Checker, der im Erfolgsfall
nichts tut und im Fehlerfall AccessDeniedError wirft.
"""
from __future__ import annotations

import unittest

from core.access.checker import AccessDeniedError
from core.services.inventory_service import InventoryService


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
