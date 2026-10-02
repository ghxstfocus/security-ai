# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer Migration 0012 (devices.last_ip).

ALTER TABLE ADD COLUMN. Spalte ist nullable.
"""
from __future__ import annotations

import sqlite3
import unittest

from core.inventory.repository import (
    DEFAULT_MIGRATIONS_DIR,
    apply_migrations,
    connect,
)


class Migration0012Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn: sqlite3.Connection = connect(":memory:")
        apply_migrations(self.conn, DEFAULT_MIGRATIONS_DIR)

    def tearDown(self) -> None:
        self.conn.close()

    def test_column_exists(self) -> None:
        rows = self.conn.execute(
            "PRAGMA table_info(devices)"
        ).fetchall()
        cols = {r[1] for r in rows}
        self.assertIn("last_ip", cols)

    def test_column_nullable(self) -> None:
        # Alt-Eintraege haben NULL -> Spalte ist nullable.
        rows = self.conn.execute(
            "PRAGMA table_info(devices)"
        ).fetchall()
        by_name = {r[1]: r for r in rows}
        # r[3] = notnull (0 = nullable)
        self.assertEqual(by_name["last_ip"][3], 0)

    def test_insert_with_last_ip(self) -> None:
        self.conn.execute(
            "INSERT INTO devices "
            "(identifier, entity_name, network_type, "
            "first_seen, last_seen, notes, last_ip) "
            "VALUES (?, ?, ?, ?, ?, NULL, ?)",
            ("aa:bb:cc:dd:ee:01", "test", "Hauptnetz",
             "2026-09-28T10:00:00+00:00",
             "2026-09-28T10:00:00+00:00",
             "10.0.0.5"),
        )
        row = self.conn.execute(
            "SELECT last_ip FROM devices WHERE identifier = ?",
            ("aa:bb:cc:dd:ee:01",),
        ).fetchone()
        self.assertEqual(row[0], "10.0.0.5")

    def test_insert_without_last_ip(self) -> None:
        self.conn.execute(
            "INSERT INTO devices "
            "(identifier, entity_name, network_type, "
            "first_seen, last_seen, notes) "
            "VALUES (?, ?, ?, ?, ?, NULL)",
            ("aa:bb:cc:dd:ee:02", "test2", "Hauptnetz",
             "2026-09-28T10:00:00+00:00",
             "2026-09-28T10:00:00+00:00"),
        )
        row = self.conn.execute(
            "SELECT last_ip FROM devices WHERE identifier = ?",
            ("aa:bb:cc:dd:ee:02",),
        ).fetchone()
        self.assertIsNone(row[0])

    def test_idempotent_reapply(self) -> None:
        # apply_migrations ueberspringt 0012 beim zweiten Lauf.
        # Kein ALTER-Error (Spalte existiert schon).
        apply_migrations(self.conn, DEFAULT_MIGRATIONS_DIR)
        rows = self.conn.execute(
            "PRAGMA table_info(devices)"
        ).fetchall()
        cols = [r[1] for r in rows]
        # last_ip darf nur einmal vorkommen.
        self.assertEqual(cols.count("last_ip"), 1)


if __name__ == "__main__":
    unittest.main()
