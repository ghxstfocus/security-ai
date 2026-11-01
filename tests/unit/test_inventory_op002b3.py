# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer OP-002b3: upsert_seen schreibt last_ip-Wechsel in device_history.

Akzeptanzkriterien aus docs/STATUS.md OP-002b3:
- In upsert_seen, NACH erfolgreichem update_last_ip_if_changed
- Bei True: _insert_device_history(device_id, feld=last_ip,
  alt=<alter Wert>, neu=<normalize_ip(ip)>, timestamp=ts)
- Atomare Transaktion (commit am Ende, nicht in update_last_ip_if_changed)
- KEINE Inline-Implementierung der History-Logik
"""
from __future__ import annotations

import unittest

from core.inventory.repository import DeviceRepository, apply_migrations, connect


def _fresh_conn():
    conn = connect(":memory:")
    apply_migrations(conn)
    return conn


class UpsertSeenIpWechselHistoryTests(unittest.TestCase):
    def setUp(self):
        self.conn = _fresh_conn()
        self.repo = DeviceRepository(self.conn)

    def tearDown(self):
        self.conn.close()

    def _history(self, device_id: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT event_type, feld, alt, neu, timestamp "
            "FROM device_history WHERE device_id = ? ORDER BY id",
            (device_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def test_upsert_seen_mit_ip_wechsel_history(self):
        """OP-Pflichtfall: Wechsel 192.0.2.10 -> 192.0.2.11 erzeugt 1 Eintrag."""
        # Erst-Aufruf: keine History-Zeile fuer field_change
        d1 = self.repo.upsert_seen("host-1", ip="192.0.2.10")
        self.assertIsNotNone(d1.id)
        h1 = self._history(d1.id)
        feld_changes_1 = [e for e in h1 if e["event_type"] == "field_change"]
        self.assertEqual(len(feld_changes_1), 0, "Erst-Insert: kein field_change")

        # Zweiter Aufruf: IP-Wechsel -> 1 field_change-Eintrag
        d2 = self.repo.upsert_seen("host-1", ip="192.0.2.11")
        self.assertEqual(d2.last_ip, "192.0.2.11")
        h2 = self._history(d2.id)
        feld_changes_2 = [e for e in h2 if e["event_type"] == "field_change"]
        self.assertEqual(len(feld_changes_2), 1, "Wechsel: 1 field_change")
        fc = feld_changes_2[0]
        self.assertEqual(fc["feld"], "last_ip")
        self.assertEqual(fc["alt"], "192.0.2.10")
        self.assertEqual(fc["neu"], "192.0.2.11")

        # DB-Zustand nach Act 2
        row = self.conn.execute(
            "SELECT last_ip FROM devices WHERE identifier = ?", ("host-1",)
        ).fetchone()
        self.assertEqual(row["last_ip"], "192.0.2.11")
        hist_rows = self.conn.execute(
            "SELECT feld, alt, neu, timestamp FROM device_history "
            "WHERE device_id = ? AND feld = 'last_ip'",
            (d2.id,),
        ).fetchall()
        self.assertEqual(len(hist_rows), 1)
        self.assertEqual(hist_rows[0]["alt"], "192.0.2.10")
        self.assertEqual(hist_rows[0]["neu"], "192.0.2.11")
        self.assertEqual(str(hist_rows[0]["timestamp"]), d2.last_seen.isoformat())

    def test_upsert_seen_ohne_ip_wechsel_kein_history_eintrag(self):
        """Gleiche IP nochmal -> kein field_change-Eintrag."""
        self.repo.upsert_seen("host-2", ip="192.0.2.20")
        d = self.repo.upsert_seen("host-2", ip="192.0.2.20")
        self.assertEqual(d.last_ip, "192.0.2.20")
        h = self._history(d.id)
        feld_changes = [e for e in h if e["event_type"] == "field_change"]
        self.assertEqual(len(feld_changes), 0, "kein Wechsel: kein field_change")

        # DB-Zustand: genau eine devices-Zeile fuer host-2
        rows = self.conn.execute(
            "SELECT last_ip FROM devices WHERE identifier = ?", ("host-2",)
        ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["last_ip"], "192.0.2.20")


if __name__ == "__main__":
    unittest.main()
