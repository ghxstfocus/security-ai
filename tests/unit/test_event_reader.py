"""Tests fuer tools/event_reader.py (A1212).

Fritz!Box-Zugriffe und SecurityAI werden gemockt.
Kein Netzwerk, kein echter process()-Aufruf.
"""
from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from core.events.event import Event, EventType, Severity, new_event
from core.inventory.repository import (
    DEFAULT_MIGRATIONS_DIR,
    apply_migrations,
    connect,
)
from tools import event_reader as er


def _seed_conn(tmp_path: Path) -> sqlite3.Connection:
    db = tmp_path / "x.db"
    conn = connect(db)
    apply_migrations(conn, DEFAULT_MIGRATIONS_DIR)
    return conn


def _make_event(mac: str = "aa:bb:cc:dd:ee:01") -> Event:
    return new_event(
        source="fritzbox",
        event_type=EventType.DEVICE_PRESENCE.value,
        severity=Severity.INFO,
        data={
            "identifier": mac,
            "mac": mac,
            "ip": "10.0.0.1",
            "entity_name": "kamera",
            "network_type": "Hauptnetz",
        },
    )


class CursorTests(unittest.TestCase):
    def test_read_cursor_default(self) -> None:
        with TemporaryDirectory() as d:
            conn = _seed_conn(Path(d))
            try:
                fname, off = er._read_cursor(conn)
                self.assertEqual(fname, "")
                self.assertEqual(off, 0)
            finally:
                conn.close()

    def test_write_then_read(self) -> None:
        with TemporaryDirectory() as d:
            conn = _seed_conn(Path(d))
            try:
                er._write_cursor(conn, "events-2026-09-28.jsonl", 42)
                fname, off = er._read_cursor(conn)
                self.assertEqual(fname, "events-2026-09-28.jsonl")
                self.assertEqual(off, 42)
            finally:
                conn.close()


class MarkProcessingTests(unittest.TestCase):
    def test_first_mark_true(self) -> None:
        with TemporaryDirectory() as d:
            conn = _seed_conn(Path(d))
            try:
                self.assertTrue(er._mark_processing(conn, "EVT-1"))
            finally:
                conn.close()

    def test_second_mark_false(self) -> None:
        with TemporaryDirectory() as d:
            conn = _seed_conn(Path(d))
            try:
                self.assertTrue(er._mark_processing(conn, "EVT-1"))
                self.assertFalse(er._mark_processing(conn, "EVT-1"))
            finally:
                conn.close()

    def test_unmark_removes(self) -> None:
        with TemporaryDirectory() as d:
            conn = _seed_conn(Path(d))
            try:
                er._mark_processing(conn, "EVT-1")
                er._unmark_processing(conn, "EVT-1")
                count = conn.execute(
                    "SELECT COUNT(*) FROM processed_events"
                ).fetchone()[0]
                self.assertEqual(count, 0)
            finally:
                conn.close()

    def test_unmark_missing_no_error(self) -> None:
        with TemporaryDirectory() as d:
            conn = _seed_conn(Path(d))
            try:
                er._unmark_processing(conn, "EVT-none")
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()


class RunTests(unittest.TestCase):
    def _patch_checks(self):
        """check_audit_logs und check_schema_version erfolgreich."""
        return (
            mock.patch.object(er, "check_audit_logs"),
            mock.patch.object(er, "check_schema_version"),
        )

    def _patch_ai(self, process_side_effect=None):
        """SecurityAI gemockt: process() nach Wahl, close() no-op."""
        ai = mock.MagicMock()
        if process_side_effect is not None:
            ai.process.side_effect = process_side_effect
        return ai

    def test_audit_check_fail_exit_1(self) -> None:
        from harness.audit.writer import AuditDirInconsistentError
        with mock.patch.object(
            er, "check_audit_logs",
            side_effect=AuditDirInconsistentError("kaputt"),
        ):
            self.assertEqual(er.run(), 1)

    def test_schema_check_fail_exit_2(self) -> None:
        from core.inventory.repository import SchemaVersionError
        with mock.patch.object(
            er, "check_audit_logs",
        ), mock.patch.object(
            er, "check_schema_version",
            side_effect=SchemaVersionError("alt"),
        ):
            self.assertEqual(er.run(), 2)

    def test_empty_no_events_exit_0(self) -> None:
        ai = self._patch_ai()
        with TemporaryDirectory() as d:
            db = Path(d) / "x.db"
            conn = connect(db)
            apply_migrations(conn, DEFAULT_MIGRATIONS_DIR)
            conn.close()
            events = Path(d) / "events-2026-09-28.jsonl"
            # Events-Datei fehlt absichtlich.
            with mock.patch.object(
                er, "check_audit_logs",
            ), mock.patch.object(
                er, "check_schema_version",
            ), mock.patch.object(
                er, "connect", return_value=connect(db),
            ), mock.patch.object(
                er, "SecurityAI", return_value=ai,
            ), mock.patch.object(
                er, "_EVENTS_DIR", Path(d),
            ):
                self.assertEqual(er.run(), 0)
            self.assertEqual(ai.process.call_count, 0)

    def test_n_events_new_n_process(self) -> None:
        ai = self._patch_ai()
        with TemporaryDirectory() as d:
            db = Path(d) / "x.db"
            conn = connect(db)
            apply_migrations(conn, DEFAULT_MIGRATIONS_DIR)
            conn.close()
            ev = [_make_event(f"aa:bb:cc:dd:ee:0{i}") for i in range(3)]
            f = Path(d) / ("events-" + datetime.now(UTC).strftime(
                "%Y-%m-%d") + ".jsonl")
            f.write_text(
                "\n".join(e.to_json() for e in ev) + "\n",
                encoding="utf-8",
            )
            with mock.patch.object(
                er, "check_audit_logs",
            ), mock.patch.object(
                er, "check_schema_version",
            ), mock.patch.object(
                er, "connect", return_value=connect(db),
            ), mock.patch.object(
                er, "SecurityAI", return_value=ai,
            ), mock.patch.object(
                er, "_EVENTS_DIR", Path(d),
            ):
                self.assertEqual(er.run(), 0)
            self.assertEqual(ai.process.call_count, 3)

    def test_already_processed_skip(self) -> None:
        ai = self._patch_ai()
        with TemporaryDirectory() as d:
            db = Path(d) / "x.db"
            conn = connect(db)
            apply_migrations(conn, DEFAULT_MIGRATIONS_DIR)
            ev = _make_event("aa:bb:cc:dd:ee:99")
            conn.execute(
                "INSERT INTO processed_events (event_id, processed_at) "
                "VALUES (?, ?)", (ev.event_id, "2026-09-28T20:00:00+00:00"),
            )
            conn.commit()
            conn.close()
            f = Path(d) / ("events-" + datetime.now(UTC).strftime(
                "%Y-%m-%d") + ".jsonl")
            f.write_text(ev.to_json() + "\n", encoding="utf-8")
            with mock.patch.object(
                er, "check_audit_logs",
            ), mock.patch.object(
                er, "check_schema_version",
            ), mock.patch.object(
                er, "connect", return_value=connect(db),
            ), mock.patch.object(
                er, "SecurityAI", return_value=ai,
            ), mock.patch.object(
                er, "_EVENTS_DIR", Path(d),
            ):
                self.assertEqual(er.run(), 0)
            self.assertEqual(ai.process.call_count, 0)

    def test_process_fail_unmark_and_exit_3(self) -> None:
        ai = self._patch_ai(process_side_effect=RuntimeError("kaputt"))
        with TemporaryDirectory() as d:
            db = Path(d) / "x.db"
            conn = connect(db)
            apply_migrations(conn, DEFAULT_MIGRATIONS_DIR)
            conn.close()
            ev = _make_event("aa:bb:cc:dd:ee:77")
            f = Path(d) / ("events-" + datetime.now(UTC).strftime(
                "%Y-%m-%d") + ".jsonl")
            f.write_text(ev.to_json() + "\n", encoding="utf-8")
            with mock.patch.object(
                er, "check_audit_logs",
            ), mock.patch.object(
                er, "check_schema_version",
            ), mock.patch.object(
                er, "connect", return_value=connect(db),
            ), mock.patch.object(
                er, "SecurityAI", return_value=ai,
            ), mock.patch.object(
                er, "_EVENTS_DIR", Path(d),
            ):
                self.assertEqual(er.run(), 3)
            check = connect(db)
            try:
                cnt = check.execute(
                    "SELECT COUNT(*) FROM processed_events"
                ).fetchone()[0]
                self.assertEqual(cnt, 0)
            finally:
                check.close()

    def test_tageswechsel_reset_offset(self) -> None:
        ai = self._patch_ai()
        with TemporaryDirectory() as d:
            db = Path(d) / "x.db"
            conn = connect(db)
            apply_migrations(conn, DEFAULT_MIGRATIONS_DIR)
            conn.execute(
                "UPDATE event_cursor SET file_name = ?, line_offset = ? "
                "WHERE id = 1",
                ("events-2026-01-01.jsonl", 99),
            )
            conn.commit()
            conn.close()
            ev = _make_event("aa:bb:cc:dd:ee:aa")
            f = Path(d) / ("events-" + datetime.now(UTC).strftime(
                "%Y-%m-%d") + ".jsonl")
            f.write_text(ev.to_json() + "\n", encoding="utf-8")
            with mock.patch.object(
                er, "check_audit_logs",
            ), mock.patch.object(
                er, "check_schema_version",
            ), mock.patch.object(
                er, "connect", return_value=connect(db),
            ), mock.patch.object(
                er, "SecurityAI", return_value=ai,
            ), mock.patch.object(
                er, "_EVENTS_DIR", Path(d),
            ):
                self.assertEqual(er.run(), 0)
            check = connect(db)
            try:
                row = check.execute(
                    "SELECT file_name, line_offset FROM event_cursor "
                    "WHERE id = 1"
                ).fetchone()
                self.assertEqual(
                    row[0],
                    "events-" + datetime.now(UTC).strftime("%Y-%m-%d")
                    + ".jsonl",
                )
                self.assertEqual(row[1], 1)
            finally:
                check.close()
            self.assertEqual(ai.process.call_count, 1)


if __name__ == "__main__":
    unittest.main()
