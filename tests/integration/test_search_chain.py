"""
Integrationstest: Suche ueber echte SQLite (3.6.16, A546).
"""
from __future__ import annotations

import unittest
from pathlib import Path
import tempfile

from core.search.repository import SearchRepository
from core.services.search_service import SearchService
from tests.unit._helpers import migrated_conn


class _Checker:
    def permissions_of(self, actor):
        return frozenset({
            "device.read", "change.view", "approval.view",
            "principal.manage", "role.manage", "audit.read",
        })


class SearchChainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.conn = migrated_conn(self.tmp_path)
        # Drei Quellen mit gemeinsamem Begriff "kamera".
        self.conn.execute(
            "INSERT INTO devices (identifier, entity_name, network_type, "
            "first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
            ("192.168.178.50", "kamera-hof", "Hauptnetz",
             "2026-09-26T10:00:00+00:00", "2026-09-26T10:00:00+00:00"),
        )
        self.conn.execute(
            "INSERT INTO change_requests (change_id, timestamp, title, "
            "description, requested_by, status, type, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("CHG-2026-01000", "2026-09-26T10:00:00+00:00",
             "kamera-umbau", "d", "admin-web", "draft",
             "config_change", "2026-09-26T10:00:00+00:00"),
        )
        self.conn.execute(
            "INSERT INTO approvals (request_id, timestamp, tool_name, "
            "args_json, requested_by, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("APR-2026-01000", "2026-09-26T10:00:00+00:00",
             "kamera_scan", "[]", "admin-web", "pending",
             "2026-09-26T10:00:00+00:00"),
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_kategorie_im_risk_assessment_suchbar(self):
        # A738: category wird durchsucht.
        ra = [
            {"audit_id": "AUD-X", "event_id": "EVT-X",
             "rule_id": "port_scan", "tool": "risk_engine",
             "category": "CONFIRMED"},
        ]
        svc = SearchService(
            repo=SearchRepository(self.conn),
            audit_reader=lambda **kw: ra,
            checker=_Checker(),
        )
        result = svc.search("admin1", "confirmed")
        assert "risk_assessments" in result
        assert result["risk_assessments"][0]["category"] == "CONFIRMED"

    def test_drei_quellen(self):
        svc = SearchService(
            repo=SearchRepository(self.conn),
            audit_reader=lambda **kw: [],
            checker=_Checker(),
        )
        result = svc.search("admin1", "kamera")
        self.assertIn("devices", result)
        self.assertIn("changes", result)
        self.assertIn("approvals", result)
        self.assertEqual(result["devices"][0]["identifier"],
                         "192.168.178.50")
        self.assertEqual(result["changes"][0]["change_id"],
                         "CHG-2026-01000")


if __name__ == "__main__":
    unittest.main()
