# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tests fuer ChangeApplier-Stub und orchestrator.create_change_request.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from apps.security_ai.orchestrator import SecurityAI
from core.changes.models import ChangeStatus, ChangeType
from core.changes.repository import ChangeRepository
from core.inventory.repository import connect
from harness.versioning.applier import ChangeApplier


class ApplierStubTests(unittest.TestCase):
    def test_apply_wirft_notimplemented(self):
        a = ChangeApplier()
        with self.assertRaises(NotImplementedError):
            a.apply(mock.Mock())

    def test_rollback_wirft_notimplemented(self):
        a = ChangeApplier()
        with self.assertRaises(NotImplementedError):
            a.rollback(mock.Mock())

    def test_konstruktor_nimmt_deps(self):
        a = ChangeApplier(audit="x", repo="y")
        self.assertEqual(a._deps, {"audit": "x", "repo": "y"})


class OrchestratorCreateChangeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.app = SecurityAI(
            db_path=self.tmp / "inv.db",
            migrations_dir="data/migrations",
            audit_base_dir=self.tmp / "audit-logs",
            app_config_path=self.tmp / "cfg.yaml",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_create_change_request_legt_draft_an(self):
        cr = self.app.create_change_request(
            title="Firewall-Regel",
            description="Block outbound SSH",
            type=ChangeType.FIREWALL_CHANGE,
            files_affected=["policies/tools.yaml"],
        )
        self.assertEqual(cr.status, ChangeStatus.DRAFT)
        self.assertEqual(cr.type, ChangeType.FIREWALL_CHANGE)
        self.assertEqual(cr.requested_by, "security_ai")
        self.assertEqual(cr.files_affected, ["policies/tools.yaml"])
        self.assertTrue(cr.change_id.startswith("CHG-"))

        # In DB nachvollziehbar
        conn = connect(self.tmp / "inv.db")
        repo = ChangeRepository(conn)
        back = repo.get(cr.change_id)
        conn.close()
        self.assertEqual(back.change_id, cr.change_id)
        self.assertEqual(back.status, ChangeStatus.DRAFT)

    def test_create_change_request_audit_kind(self):
        cr = self.app.create_change_request(
            title="T",
            description="D",
            type=ChangeType.POLICY_CHANGE,
        )
        files = list((self.tmp / "audit-logs").glob("*.jsonl"))
        self.assertEqual(len(files), 1)
        kinds = []
        for line in files[0].read_text().splitlines():
            entry = json.loads(line)
            kinds.append(entry["details"]["kind"])
        self.assertIn("change_created", kinds)
        # Audit-Details enthalten change_id
        for line in files[0].read_text().splitlines():
            entry = json.loads(line)
            if entry["details"]["kind"] == "change_created":
                self.assertEqual(
                    entry["details"]["change_id"], cr.change_id)
                self.assertEqual(entry["details"]["type"],
                                 "policy_change")


if __name__ == "__main__":
    unittest.main()
