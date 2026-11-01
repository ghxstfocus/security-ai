# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer OP-002b2: _insert_device_history mit Duplikatschutz.

Akzeptanzkriterien aus docs/STATUS.md OP-002b2:
- Neue Methode _insert_device_history(device_id, feld, alt, neu, timestamp)
- VOR dem INSERT ein SELECT auf (device_id, feld, alt, neu, timestamp)
- Duplikat -> skip (return False)
- KEINE doppelte Methodendefinition
- KEIN Aufruf aus upsert_seen (bleibt OP-002b3)
"""
from __future__ import annotations

import unittest
from datetime import UTC, datetime

from core.inventory.repository import DeviceRepository, apply_migrations, connect


def _fresh_conn():
    conn = connect(":memory:")
    apply_migrations(conn)
    return conn


TS = "2026-11-01T12:00:00+00:00"


class InsertDeviceHistoryTests(unittest.TestCase):
    def setUp(self):
        self.conn = _fresh_conn()
        self.repo = DeviceRepository(self.conn)
        now = datetime.now(UTC).isoformat()
        cur = self.conn.execute(
            "INSERT INTO devices "
            "(identifier, first_seen, last_seen) "
            "VALUES (?, ?, ?)",
            ("dev1", now, now),
        )
        self.device_id = cur.lastrowid
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def _count_history(self) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM device_history WHERE device_id = ?",
            (self.device_id,),
        ).fetchone()
        return int(row["n"])

    def test_insert_device_history_kein_duplikat(self):
        """OP-Pflichtfall: 2x gleicher Aufruf -> 1 DB-Zeile."""
        r1 = self.repo._insert_device_history(
            self.device_id, "last_ip", "1.1.1.1", "2.2.2.2", TS,
        )
        self.assertTrue(r1)
        r2 = self.repo._insert_device_history(
            self.device_id, "last_ip", "1.1.1.1", "2.2.2.2", TS,
        )
        self.assertFalse(r2)
        self.assertEqual(self._count_history(), 1)

    def test_insert_device_history_alt_none_kein_duplikat(self):
        """NULL-sicher: alt=None beim 2. Aufruf -> Duplikat erkannt."""
        r1 = self.repo._insert_device_history(
            self.device_id, "last_ip", None, "1.1.1.1", TS,
        )
        self.assertTrue(r1)
        # Klassisches "alt = NULL" wuerde hier NICHT greifen (SQL-Semantik),
        # daher testet dieser Fall die IS-?-Syntax explizit.
        r2 = self.repo._insert_device_history(
            self.device_id, "last_ip", None, "1.1.1.1", TS,
        )
        self.assertFalse(r2)
        self.assertEqual(self._count_history(), 1)

    def test_insert_device_history_anderer_timestamp_kein_duplikat(self):
        """Gleiche Feld-Aenderung zu anderem ts -> 2 Zeilen."""
        ts2 = "2026-11-01T12:00:01+00:00"
        r1 = self.repo._insert_device_history(
            self.device_id, "last_ip", "1.1.1.1", "2.2.2.2", TS,
        )
        r2 = self.repo._insert_device_history(
            self.device_id, "last_ip", "1.1.1.1", "2.2.2.2", ts2,
        )
        self.assertTrue(r1)
        self.assertTrue(r2)
        self.assertEqual(self._count_history(), 2)


if __name__ == "__main__":
    unittest.main()
