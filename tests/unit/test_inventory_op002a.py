# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer OP-002a: normalize_ip + update_last_ip_if_changed.

Akzeptanzkriterien aus docs/STATUS.md OP-002a:
- normalize_ip: None/"" -> None, parsebar -> kanonisch, unparsebar -> None
- update_last_ip_if_changed: Erstschreiben/Wchsel -> True, unveraendert
  oder unbekannt -> False, DB nur bei Diff geaendert
"""
from __future__ import annotations

import unittest
from datetime import UTC, datetime

from core.inventory.device import normalize_ip
from core.inventory.repository import DeviceRepository, apply_migrations, connect


def _fresh_conn():
    conn = connect(":memory:")
    apply_migrations(conn)
    return conn


# ---------------------------------------------------------------------
# normalize_ip: 5 Faelle
# ---------------------------------------------------------------------

class NormalizeIpTests(unittest.TestCase):
    def test_none(self):
        self.assertIsNone(normalize_ip(None))

    def test_leerstring(self):
        self.assertIsNone(normalize_ip(""))
        self.assertIsNone(normalize_ip("   "))
        self.assertIsNone(normalize_ip("\t\n"))

    def test_ipv4(self):
        self.assertEqual(normalize_ip("192.168.1.1"), "192.168.1.1")
        self.assertEqual(normalize_ip("10.0.0.255"), "10.0.0.255")

    def test_ipv6_canonical(self):
        # Kurz- und Langform muessen dasselbe Ergebnis liefern.
        self.assertEqual(normalize_ip("::1"), "::1")
        self.assertEqual(normalize_ip("0:0:0:0:0:0:0:1"), "::1")
        # Auch Gross-/Kleinschreibung
        self.assertEqual(normalize_ip("FE80::1"), "fe80::1")

    def test_unparsebar(self):
        self.assertIsNone(normalize_ip("nicht-eine-ip"))
        self.assertIsNone(normalize_ip("300.300.300.300"))
        self.assertIsNone(normalize_ip("1.2.3"))
        self.assertIsNone(normalize_ip("1.2.3.4.5"))


# ---------------------------------------------------------------------
# update_last_ip_if_changed: 4 Faelle (Erstschreiben, unveraendert,
# Wechsel, unbekannt)
# ---------------------------------------------------------------------

class UpdateLastIpIfChangedTests(unittest.TestCase):
    def setUp(self):
        self.conn = _fresh_conn()
        self.repo = DeviceRepository(self.conn)
        # Direkt in DB — keine Abhaengigkeit von upsert_seen
        now = datetime.now(UTC).isoformat()
        self.conn.execute(
            "INSERT INTO devices "
            "(identifier, last_ip, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?)",
            ("dev1", "192.168.1.1", now, now),
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def _get_last_ip(self, identifier: str) -> str | None:
        row = self.conn.execute(
            "SELECT last_ip FROM devices WHERE identifier = ?",
            (identifier,),
        ).fetchone()
        return row["last_ip"] if row else None

    def test_erstschreiben(self):
        """Neue IP setzen -> True, DB enthaelt neue IP."""
        r = self.repo.update_last_ip_if_changed("dev1", "192.168.1.2")
        self.assertTrue(r)
        self.assertEqual(self._get_last_ip("dev1"), "192.168.1.2")

    def test_unveraendert(self):
        """Gleiche IP nochmal -> False, keine DB-Aenderung."""
        r = self.repo.update_last_ip_if_changed("dev1", "192.168.1.1")
        self.assertFalse(r)
        self.assertEqual(self._get_last_ip("dev1"), "192.168.1.1")

    def test_wechsel_mit_ipv6(self):
        """IPv6-Wechsel -> True, kanonische Form in DB."""
        r = self.repo.update_last_ip_if_changed("dev1", "0:0:0:0:0:0:0:1")
        self.assertTrue(r)
        self.assertEqual(self._get_last_ip("dev1"), "::1")

    def test_unbekannter_identifier(self):
        """Unbekannter identifier -> False, kein Crash."""
        r = self.repo.update_last_ip_if_changed("nicht-vorhanden", "10.0.0.1")
        self.assertFalse(r)


if __name__ == "__main__":
    unittest.main()
