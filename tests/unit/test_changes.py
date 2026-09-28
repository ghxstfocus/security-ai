"""
Tests fuer Change Requests: Modell, Repository, Parser, CLI.

CLI-Tests nutzen tmp-SQLite-Datei (Migration laeuft).
Audit landet in tmp-Verzeichnis.
"""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from core.changes.models import (
    ChangeStatus,
    ChangeType,
    utc_now_iso,
)
from core.changes.parser import (
    ChangeParserError,
    change_from_dict,
    change_to_dict,
    change_to_json,
    default_path,
    read_change_file,
    write_change_file,
)
from core.changes.repository import (
    ChangeNotFoundError,
    ChangeRepository,
    ChangeStateError,
)
from core.inventory.repository import apply_migrations, connect
from scripts.changes_cli import main as changes_main

# ---------------------------------------------------------------------- #
# Parser
# ---------------------------------------------------------------------- #

def _min_dict(change_id: str = "CHG-2026-00001") -> dict:
    return {
        "change_id": change_id,
        "timestamp": utc_now_iso(),
        "title": "Test",
        "description": "desc",
        "requested_by": "security_ai",
        "status": "draft",
        "type": "firewall_change",
    }


class ParserTests(unittest.TestCase):
    def test_minimal_ok(self):
        cr = change_from_dict(_min_dict())
        self.assertIs(cr.status, ChangeStatus.DRAFT)
        self.assertIs(cr.type, ChangeType.FIREWALL_CHANGE)
        self.assertIsNone(cr.files_affected)

    def test_roundtrip_to_dict(self):
        cr = change_from_dict(_min_dict())
        d = change_to_dict(cr)
        self.assertNotIn("id", d)
        self.assertIn("created_at", d)
        cr2 = change_from_dict(d)
        self.assertEqual(cr2.change_id, cr.change_id)
        self.assertEqual(cr2.created_at, cr.created_at)

    def test_json_string(self):
        cr = change_from_dict(_min_dict())
        s = change_to_json(cr)
        parsed = json.loads(s)
        self.assertEqual(parsed["status"], "draft")
        self.assertEqual(parsed["type"], "firewall_change")
        self.assertNotIn("id", parsed)

    def test_fehlende_pflicht(self):
        d = _min_dict()
        del d["title"]
        with self.assertRaises(ChangeParserError):
            change_from_dict(d)

    def test_unbekanntes_feld(self):
        d = _min_dict()
        d["unbekannt"] = 1
        with self.assertRaises(ChangeParserError):
            change_from_dict(d)

    def test_ungueltiger_status(self):
        d = _min_dict()
        d["status"] = "unbekannt"
        with self.assertRaises(ChangeParserError):
            change_from_dict(d)

    def test_ungueltiger_type(self):
        d = _min_dict()
        d["type"] = "unbekannt"
        with self.assertRaises(ChangeParserError):
            change_from_dict(d)

    def test_naiver_timestamp(self):
        d = _min_dict()
        d["timestamp"] = "2026-01-01T00:00:00"
        with self.assertRaises(ChangeParserError):
            change_from_dict(d)

    def test_naiver_created_at(self):
        d = _min_dict()
        d["created_at"] = "2026-01-01T00:00:00"
        with self.assertRaises(ChangeParserError):
            change_from_dict(d)

    def test_files_affected_falscher_typ(self):
        d = _min_dict()
        d["files_affected"] = "kein-array"
        with self.assertRaises(ChangeParserError):
            change_from_dict(d)

    def test_risk_score_falscher_typ(self):
        d = _min_dict()
        d["risk_score"] = "hoch"
        with self.assertRaises(ChangeParserError):
            change_from_dict(d)

    def test_datei_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            cr = change_from_dict(_min_dict("CHG-2026-00099"))
            p = write_change_file(cr, base_dir=tmp)
            self.assertTrue(p.exists())
            back = read_change_file(p)
            self.assertEqual(back.change_id, "CHG-2026-00099")

    def test_default_path_traversal(self):
        for bad in ["CHG/../../etc/passwd", "CHG\\x", "CHG-../x",
                    "CHG-\x00"]:
            with self.assertRaises(ChangeParserError):
                default_path(bad)

    def test_read_change_file_fehlt(self):
        with self.assertRaises(ChangeParserError):
            read_change_file("/tmp/gibts-nicht-xyz-changes.json")


# ---------------------------------------------------------------------- #
# Repository
# ---------------------------------------------------------------------- #

class RepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.db = self.tmp / "inv.db"
        conn = connect(self.db)
        apply_migrations(conn, "data/migrations")
        conn.close()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _repo(self) -> ChangeRepository:
        conn = connect(self.db)
        return ChangeRepository(conn)

    def test_id_vergabe_jahresweise(self):
        repo = self._repo()
        a = repo.create(title="a", description="d",
                        requested_by="u", type=ChangeType.CODE_CHANGE)
        b = repo.create(title="b", description="d",
                        requested_by="u", type=ChangeType.CODE_CHANGE)
        self.assertEqual(a.change_id, "CHG-2026-00001")
        self.assertEqual(b.change_id, "CHG-2026-00002")

    def test_voller_fluss(self):
        repo = self._repo()
        r = repo.create(title="x", description="y",
                        requested_by="u", type=ChangeType.POLICY_CHANGE)
        r = repo.transition(r.change_id, ChangeStatus.TESTING)
        r = repo.transition(r.change_id, ChangeStatus.PENDING_REVIEW)
        r = repo.transition(r.change_id, ChangeStatus.APPROVED,
                            decided_by="admin", reason="ok")
        self.assertEqual(r.status, ChangeStatus.APPROVED)
        self.assertEqual(r.decided_by, "admin")
        r = repo.transition(r.change_id, ChangeStatus.DEPLOYED)
        self.assertIsNotNone(r.deployed_at)
        r = repo.transition(r.change_id, ChangeStatus.ROLLED_BACK,
                            decided_by="admin", reason="kaputt")
        self.assertIsNotNone(r.rolled_back_at)

    def test_verbotener_uebergang(self):
        repo = self._repo()
        r = repo.create(title="x", description="y",
                        requested_by="u", type=ChangeType.CODE_CHANGE)
        with self.assertRaises(ChangeStateError):
            repo.transition(r.change_id, ChangeStatus.DEPLOYED)

    def test_cancel_aus_draft(self):
        repo = self._repo()
        r = repo.create(title="x", description="y",
                        requested_by="u", type=ChangeType.CODE_CHANGE)
        r2 = repo.transition(r.change_id, ChangeStatus.CANCELLED,
                             decided_by="u", reason="zurueckgezogen")
        self.assertEqual(r2.status, ChangeStatus.CANCELLED)
        self.assertEqual(r2.decision_reason, "zurueckgezogen")

    def test_cancel_aus_approved(self):
        repo = self._repo()
        r = repo.create(title="x", description="y",
                        requested_by="u", type=ChangeType.CODE_CHANGE)
        repo.transition(r.change_id, ChangeStatus.PENDING_REVIEW)
        repo.transition(r.change_id, ChangeStatus.APPROVED,
                        decided_by="admin")
        r2 = repo.transition(r.change_id, ChangeStatus.CANCELLED,
                             decided_by="u", reason="doch nicht")
        self.assertEqual(r2.status, ChangeStatus.CANCELLED)

    def test_approved_nach_rejected_verboten(self):
        repo = self._repo()
        r = repo.create(title="x", description="y",
                        requested_by="u", type=ChangeType.CODE_CHANGE)
        repo.transition(r.change_id, ChangeStatus.PENDING_REVIEW)
        repo.transition(r.change_id, ChangeStatus.APPROVED,
                        decided_by="admin")
        with self.assertRaises(ChangeStateError):
            repo.transition(r.change_id, ChangeStatus.REJECTED,
                            decided_by="admin")

    def test_cancelled_ist_final(self):
        repo = self._repo()
        r = repo.create(title="x", description="y",
                        requested_by="u", type=ChangeType.CODE_CHANGE)
        repo.transition(r.change_id, ChangeStatus.CANCELLED,
                        decided_by="u")
        for target in (ChangeStatus.TESTING, ChangeStatus.APPROVED,
                       ChangeStatus.REJECTED, ChangeStatus.DEPLOYED):
            with self.assertRaises(ChangeStateError):
                repo.transition(r.change_id, target, decided_by="u")

    def test_list_pending(self):
        repo = self._repo()
        a = repo.create(title="a", description="d",
                        requested_by="u", type=ChangeType.CODE_CHANGE)
        repo.create(title="b", description="d",
                    requested_by="u", type=ChangeType.CODE_CHANGE)
        self.assertEqual(repo.list_pending(), [])
        repo.transition(a.change_id, ChangeStatus.PENDING_REVIEW)
        self.assertEqual(len(repo.list_pending()), 1)

    def test_list_by_status(self):
        repo = self._repo()
        a = repo.create(title="a", description="d",
                        requested_by="u", type=ChangeType.CODE_CHANGE)
        b = repo.create(title="b", description="d",
                        requested_by="u", type=ChangeType.CODE_CHANGE)
        repo.transition(a.change_id, ChangeStatus.PENDING_REVIEW)
        drafts = repo.list_by_status(ChangeStatus.DRAFT)
        pend = repo.list_by_status(ChangeStatus.PENDING_REVIEW)
        self.assertEqual(len(drafts), 1)
        self.assertEqual(drafts[0].change_id, b.change_id)
        self.assertEqual(len(pend), 1)
        self.assertEqual(pend[0].change_id, a.change_id)

    def test_count_by_status(self):
        repo = self._repo()
        repo.create(title="a", description="d",
                    requested_by="u", type=ChangeType.CODE_CHANGE)
        repo.create(title="b", description="d",
                    requested_by="u", type=ChangeType.CODE_CHANGE)
        c = repo.count_by_status()
        self.assertEqual(c[ChangeStatus.DRAFT], 2)
        self.assertEqual(c[ChangeStatus.APPROVED], 0)

    def test_update_fields(self):
        repo = self._repo()
        r = repo.create(title="a", description="d",
                        requested_by="u", type=ChangeType.CODE_CHANGE,
                        files_affected=["x.py"])
        r2 = repo.update_fields(r.change_id,
                                description="neu",
                                files_affected=["a", "b"])
        self.assertEqual(r2.description, "neu")
        self.assertEqual(r2.files_affected, ["a", "b"])

    def test_update_fields_verboten(self):
        repo = self._repo()
        r = repo.create(title="a", description="d",
                        requested_by="u", type=ChangeType.CODE_CHANGE)
        with self.assertRaises(Exception):
            repo.update_fields(r.change_id, status="x")

    def test_not_found(self):
        repo = self._repo()
        with self.assertRaises(ChangeNotFoundError):
            repo.get("CHG-2026-99999")


# ---------------------------------------------------------------------- #
# CLI
# ---------------------------------------------------------------------- #

class ChangesCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.db = self.tmp / "inv.db"
        self.audit = self.tmp / "audit-logs"
        self.out = self.tmp / "changes"
        self.migrations = "data/migrations"
        conn = connect(self.db)
        apply_migrations(conn, self.migrations)
        conn.close()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, *args: str) -> int:
        return changes_main([
            "--db", str(self.db),
            "--migrations-dir", self.migrations,
            "--audit-base-dir", str(self.audit),
            *args,
        ])

    def _seed(self, **kw) -> str:
        conn = connect(self.db)
        repo = ChangeRepository(conn)
        r = repo.create(
            title=kw.get("title", "t"),
            description=kw.get("description", "d"),
            requested_by=kw.get("by", "security_ai"),
            type=kw.get("type", ChangeType.CODE_CHANGE),
            files_affected=kw.get("files"),
        )
        conn.close()
        return r.change_id

    def _status(self, cid: str) -> ChangeStatus:
        conn = connect(self.db)
        repo = ChangeRepository(conn)
        s = repo.get(cid).status
        conn.close()
        return s

    def test_list_leer(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self._run("list", "--all")
        self.assertEqual(rc, 0)
        self.assertIn("keine Change Requests", buf.getvalue())

    def test_create_und_show(self):
        rc = self._run("create", "--title", "T", "--description", "D",
                       "--by", "admin", "--type", "policy_change")
        self.assertEqual(rc, 0)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self._run("list", "--all")
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("CHG-2026-00001", out)
        self.assertIn("policy_change", out)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self._run("show", "CHG-2026-00001")
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("CHG-2026-00001", out)
        self.assertIn("draft", out)

    def test_create_ungueltiger_type(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = self._run("create", "--title", "T", "--description", "D",
                           "--by", "admin", "--type", "unbekannt")
        self.assertEqual(rc, 1)
        self.assertIn("FEHLER", err.getvalue())

    def test_decide_fluss(self):
        cid = self._seed()
        self._run("transition", cid, "pending_review")
        rc = self._run("decide", cid, "--by", "admin",
                       "--reason", "ok")
        self.assertEqual(rc, 0)
        self.assertEqual(self._status(cid), ChangeStatus.APPROVED)

    def test_deploy_nach_approve(self):
        cid = self._seed()
        self._run("transition", cid, "pending_review")
        self._run("decide", cid, "--by", "admin")
        rc = self._run("deploy", cid)
        self.assertEqual(rc, 0)
        self.assertEqual(self._status(cid), ChangeStatus.DEPLOYED)

    def test_deploy_ohne_approve_exit_1(self):
        cid = self._seed()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = self._run("deploy", cid)
        self.assertEqual(rc, 1)
        self.assertIn("FEHLER", err.getvalue())

    def test_reject_mit_reason(self):
        cid = self._seed()
        rc = self._run("reject", cid, "--by", "admin",
                       "--reason", "zu riskant")
        self.assertEqual(rc, 0)
        self.assertEqual(self._status(cid), ChangeStatus.REJECTED)

        conn = connect(self.db)
        repo = ChangeRepository(conn)
        self.assertEqual(
            repo.get(cid).decision_reason, "zu riskant")
        conn.close()

    def test_rollback(self):
        cid = self._seed()
        self._run("transition", cid, "pending_review")
        self._run("decide", cid, "--by", "admin")
        self._run("deploy", cid)
        rc = self._run("rollback", cid, "--by", "admin",
                       "--reason", "kaputt")
        self.assertEqual(rc, 0)
        self.assertEqual(self._status(cid), ChangeStatus.ROLLED_BACK)

    def test_cancel_cli(self):
        cid = self._seed()
        rc = self._run("cancel", cid, "--by", "u",
                       "--reason", "zurueckgezogen")
        self.assertEqual(rc, 0)
        self.assertEqual(self._status(cid), ChangeStatus.CANCELLED)

    def test_cancel_cli_unbekannt_exit_1(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = self._run("cancel", "CHG-2026-99999", "--by", "u")
        self.assertEqual(rc, 1)
        self.assertIn("FEHLER", err.getvalue())

    def test_export(self):
        cid = self._seed()
        rc = self._run("export", cid, "--out", str(self.out))
        self.assertEqual(rc, 0)
        f = self.out / f"{cid}.json"
        self.assertTrue(f.exists())
        data = json.loads(f.read_text())
        self.assertEqual(data["change_id"], cid)
        self.assertNotIn("id", data)

    def test_count(self):
        self._seed()
        self._seed()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self._run("count")
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertRegex(out, r"draft\s+2")

    def test_show_unbekannt_exit_1(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = self._run("show", "CHG-2026-99999")
        self.assertEqual(rc, 1)
        self.assertIn("FEHLER", err.getvalue())

    def test_audit_kinds(self):
        rc = self._run("create", "--title", "T", "--description", "D",
                       "--by", "admin", "--type", "config_change")
        self.assertEqual(rc, 0)
        cid = "CHG-2026-00001"
        self._run("transition", cid, "pending_review")
        self._run("decide", cid, "--by", "admin")
        self._run("deploy", cid)

        files = list(self.audit.glob("*.jsonl"))
        self.assertEqual(len(files), 1)
        kinds = []
        for line in files[0].read_text().splitlines():
            entry = json.loads(line)
            kinds.append(entry["details"]["kind"])
        self.assertIn("change_created", kinds)
        self.assertIn("change_approved", kinds)
        self.assertIn("change_deployed", kinds)

    def test_audit_kind_cancelled(self):
        rc = self._run("create", "--title", "T", "--description", "D",
                       "--by", "u", "--type", "config_change")
        self.assertEqual(rc, 0)
        cid = "CHG-2026-00001"
        rc = self._run("cancel", cid, "--by", "u",
                       "--reason", "zurueck")
        self.assertEqual(rc, 0)
        files = list(self.audit.glob("*.jsonl"))
        self.assertEqual(len(files), 1)
        kinds = []
        for line in files[0].read_text().splitlines():
            entry = json.loads(line)
            kinds.append(entry["details"]["kind"])
        self.assertIn("change_cancelled", kinds)


if __name__ == "__main__":
    unittest.main()
