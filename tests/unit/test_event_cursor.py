# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer Migration 0010 (event_cursor).

Kein Service, kein Repo. Nur: Migration erzeugt die Tabelle,
Insert idempotent, Update/Read ueber die Cursor-Zeile.
"""
from __future__ import annotations

import sqlite3
import unittest

from core.inventory.repository import (
    DEFAULT_MIGRATIONS_DIR,
    apply_migrations,
    connect,
)


class EventCursorMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn: sqlite3.Connection = connect(":memory:")
        apply_migrations(self.conn, DEFAULT_MIGRATIONS_DIR)

    def tearDown(self) -> None:
        self.conn.close()

    def test_table_exists(self) -> None:
        rows = self.conn.execute(
            "PRAGMA table_info(event_cursor)"
        ).fetchall()
        cols = {r[1] for r in rows}
        self.assertEqual(
            cols, {"id", "file_name", "line_offset", "updated_at"}
        )

    def test_initial_row(self) -> None:
        row = self.conn.execute(
            "SELECT id, file_name, line_offset, updated_at "
            "FROM event_cursor WHERE id = 1"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 1)
        self.assertEqual(row[1], "")
        self.assertEqual(row[2], 0)
        self.assertEqual(row[3], "1970-01-01T00:00:00+00:00")

    def test_idempotent_reapply(self) -> None:
        # Migration nochmal anwenden: keine zweite Zeile.
        apply_migrations(self.conn, DEFAULT_MIGRATIONS_DIR)
        count = self.conn.execute(
            "SELECT COUNT(*) FROM event_cursor"
        ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_cursor_update_and_read(self) -> None:
        self.conn.execute(
            "UPDATE event_cursor SET file_name = ?, "
            "line_offset = ?, updated_at = ? WHERE id = 1",
            ("events-2026-09-28.jsonl", 42,
             "2026-09-28T18:00:00+00:00"),
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT file_name, line_offset, updated_at "
            "FROM event_cursor WHERE id = 1"
        ).fetchone()
        self.assertEqual(row[0], "events-2026-09-28.jsonl")
        self.assertEqual(row[1], 42)
        self.assertEqual(row[2], "2026-09-28T18:00:00+00:00")


if __name__ == "__main__":
    unittest.main()
