"""
Tests fuer FritzboxStateService (T1, Auflage 1702).

Kategorie 3 (Kern-Service, RBAC, Datei-IO).
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.access.checker import AccessDeniedError
from core.services.fritzbox_state_service import (
    FritzboxStateService,
)


class _OkChecker:
    def require_permission(self, actor, code):
        return None


class _DenyChecker:
    def require_permission(self, actor, code):
        raise AccessDeniedError(f"denied: {code}")


class FritzboxStateServiceTests(unittest.TestCase):

    def test_get_state_no_file(self):
        with TemporaryDirectory() as d:
            missing = Path(d) / "no.json"
            svc = FritzboxStateService(
                checker=_OkChecker(), state_path=missing,
            )
            out = svc.get_state("admin1")
            self.assertEqual(out, {"available": False, "hosts": {}})

    def test_get_state_valid(self):
        with TemporaryDirectory() as d:
            f = Path(d) / "state.json"
            f.write_text(json.dumps({
                "hosts": {
                    "aa:bb:cc:dd:ee:01": {
                        "active": True, "ip": "10.0.0.1",
                        "name": "PC-A",
                    },
                },
            }), encoding="utf-8")
            svc = FritzboxStateService(
                checker=_OkChecker(), state_path=f,
            )
            out = svc.get_state("admin1")
            self.assertTrue(out["available"])
            self.assertIn("aa:bb:cc:dd:ee:01", out["hosts"])

    def test_get_state_malformed_json(self):
        with TemporaryDirectory() as d:
            f = Path(d) / "state.json"
            f.write_text("{not valid json", encoding="utf-8")
            svc = FritzboxStateService(
                checker=_OkChecker(), state_path=f,
            )
            out = svc.get_state("admin1")
            self.assertEqual(out, {"available": False, "hosts": {}})

    def test_get_state_rbac_denied(self):
        with TemporaryDirectory() as d:
            f = Path(d) / "state.json"
            f.write_text("{}", encoding="utf-8")
            svc = FritzboxStateService(
                checker=_DenyChecker(), state_path=f,
            )
            with self.assertRaises(AccessDeniedError):
                svc.get_state("nobody")


if __name__ == "__main__":
    unittest.main()
