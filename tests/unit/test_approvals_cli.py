"""
Tests fuer scripts/approvals_cli.py.

Nutzt eine tmp-DB (sqlite3-Datei), damit apply_migrations laeuft.
Audit landet in einem tmp-Verzeichnis; wir pruefen nicht die Audit-
Datei, nur das CLI-Verhalten und die DB-Zustaende.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.approval.models import ApprovalStatus
from core.approval.repository import ApprovalRepository
from core.inventory.repository import apply_migrations, connect
from scripts.approvals_cli import main


class ApprovalsCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.db = self.tmp / "inv.db"
        self.audit = self.tmp / "audit-logs"
        self.migrations = "data/migrations"

        # DB anlegen + migrieren
        conn = connect(self.db)
        apply_migrations(conn, self.migrations)
        conn.close()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # ------------------------------------------------------------------ #
    # Hilfen
    # ------------------------------------------------------------------ #

    def _run(self, *args: str) -> int:
        return main([
            "--db", str(self.db),
            "--migrations-dir", self.migrations,
            "--audit-base-dir", str(self.audit),
            *args,
        ])

    def _seed(self, tool_name: str = "nmap_scan",
              event_id: str | None = "evt-1",
              expires_at: str | None = None) -> str:
        conn = connect(self.db)
        repo = ApprovalRepository(conn)
        r = repo.create(
            tool_name=tool_name,
            args={"target": "192.168.178.1"},
            requested_by="security_ai",
            event_id=event_id,
            expires_at=expires_at,
        )
        conn.close()
        return r.request_id

    def _status(self, request_id: str) -> ApprovalStatus:
        conn = connect(self.db)
        repo = ApprovalRepository(conn)
        s = repo.get(request_id).status
        conn.close()
        return s

    def _reason(self, request_id: str) -> str | None:
        conn = connect(self.db)
        repo = ApprovalRepository(conn)
        r = repo.get(request_id).decision_reason
        conn.close()
        return r

    # ------------------------------------------------------------------ #
    # Tests
    # ------------------------------------------------------------------ #

    def test_list_leer(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self._run("list")
        self.assertEqual(rc, 0)
        self.assertIn("keine Approvals", buf.getvalue())

    def test_approve_unbekannte_id_exit_1(self):
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = self._run("approve", "APR-2026-99999", "--by", "admin")
        self.assertEqual(rc, 1)
        self.assertIn("FEHLER", err.getvalue())

    def test_approve_pending_setzt_granted(self):
        rid = self._seed()
        rc = self._run("approve", rid, "--by", "admin")
        self.assertEqual(rc, 0)
        self.assertIs(self._status(rid), ApprovalStatus.GRANTED)

    def test_reject_mit_reason(self):
        rid = self._seed()
        rc = self._run("reject", rid, "--by", "admin",
                       "--reason", "zu riskant")
        self.assertEqual(rc, 0)
        self.assertIs(self._status(rid), ApprovalStatus.REJECTED)
        self.assertEqual(self._reason(rid), "zu riskant")

    def test_doppeltes_approve_exit_1(self):
        rid = self._seed()
        self._run("approve", rid, "--by", "admin")
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = self._run("approve", rid, "--by", "admin")
        self.assertEqual(rc, 1)
        self.assertIn("FEHLER", err.getvalue())

    def test_count_zeigt_pending(self):
        import contextlib
        import io
        self._seed()
        self._seed()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self._run("count")
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("pending", out)
        self.assertRegex(out, r"pending\s+2")

    def test_expire_markiert_abgelaufen(self):
        rid = self._seed(expires_at="2000-01-01T00:00:00+00:00")
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self._run("expire")
        self.assertEqual(rc, 0)
        self.assertIn("1 Approval(s) auf expired gesetzt", buf.getvalue())
        self.assertIs(self._status(rid), ApprovalStatus.EXPIRED)

    def test_show_unbekannte_id_exit_1(self):
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = self._run("show", "APR-2026-99999")
        self.assertEqual(rc, 1)
        self.assertIn("FEHLER", err.getvalue())

    def test_show_zeigt_details(self):
        import contextlib
        import io
        rid = self._seed()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self._run("show", rid)
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn(rid, out)
        self.assertIn("pending", out)
        self.assertIn("nmap_scan", out)

    def test_db_fehlt_exit_1(self):
        import io
        err = io.StringIO()
        rc = main([
            "--db", str(self.tmp / "gibts-nicht.db"),
            "--migrations-dir", self.migrations,
            "--audit-base-dir", str(self.audit),
            "list",
        ])
        self.assertEqual(rc, 1)

    def test_audit_enthaelt_granted(self):
        rid = self._seed()
        self._run("approve", rid, "--by", "admin")
        files = list(self.audit.glob("*.jsonl"))
        self.assertEqual(len(files), 1)
        kinds = []
        for line in files[0].read_text().splitlines():
            entry = json.loads(line)
            kinds.append(entry["details"]["kind"])
        self.assertIn("approval_granted", kinds)

    def test_list_all_zeigt_entschiedene(self):
        import contextlib
        import io
        rid = self._seed()
        self._run("approve", rid, "--by", "admin")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self._run("list", "--all")
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn(rid, out)
        self.assertIn("granted", out)


if __name__ == "__main__":
    unittest.main()
