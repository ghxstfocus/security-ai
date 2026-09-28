"""Tests fuer Migration 0011 (processed_events).

Idempotenz-Marker fuer den Event-Reader. INSERT OR IGNORE
darf nicht mehrfach denselben event_id-Eintrag erzeugen.
"""
from __future__ import annotations

import sqlite3
import unittest

from core.inventory.repository import (
    DEFAULT_MIGRATIONS_DIR,
    apply_migrations,
    connect,
)


class ProcessedEventsMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn: sqlite3.Connection = connect(":memory:")
        apply_migrations(self.conn, DEFAULT_MIGRATIONS_DIR)

    def tearDown(self) -> None:
        self.conn.close()

    def test_table_exists(self) -> None:
        rows = self.conn.execute(
            "PRAGMA table_info(processed_events)"
        ).fetchall()
        cols = {r[1] for r in rows}
        self.assertEqual(cols, {"event_id", "processed_at"})

    def test_index_exists(self) -> None:
        rows = self.conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='index' AND name=?",
            ("idx_processed_events_processed_at",),
        ).fetchall()
        self.assertEqual(len(rows), 1)

    def test_insert_or_ignore_idempotent(self) -> None:
        cur1 = self.conn.execute(
            "INSERT OR IGNORE INTO processed_events "
            "(event_id, processed_at) VALUES (?, ?)",
            ("EVT-2026-09-28-deadbeef", "2026-09-28T20:00:00+00:00"),
        )
        self.assertEqual(cur1.rowcount, 1)
        cur2 = self.conn.execute(
            "INSERT OR IGNORE INTO processed_events "
            "(event_id, processed_at) VALUES (?, ?)",
            ("EVT-2026-09-28-deadbeef", "2026-09-28T20:01:00+00:00"),
        )
        self.assertEqual(cur2.rowcount, 0)
        count = self.conn.execute(
            "SELECT COUNT(*) FROM processed_events"
        ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_delete_removes_marker(self) -> None:
        self.conn.execute(
            "INSERT INTO processed_events "
            "(event_id, processed_at) VALUES (?, ?)",
            ("EVT-X", "2026-09-28T20:00:00+00:00"),
        )
        cur = self.conn.execute(
            "DELETE FROM processed_events WHERE event_id = ?",
            ("EVT-X",),
        )
        self.assertEqual(cur.rowcount, 1)
        count = self.conn.execute(
            "SELECT COUNT(*) FROM processed_events"
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_delete_missing_no_error(self) -> None:
        cur = self.conn.execute(
            "DELETE FROM processed_events WHERE event_id = ?",
            ("EVT-NOPE",),
        )
        self.assertEqual(cur.rowcount, 0)


if __name__ == "__main__":
    unittest.main()
