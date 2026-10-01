"""Tests fuer Inventory: Device, DeviceRepository, WhitelistRepository."""
from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

from core.inventory.device import Device, DeviceType
from core.inventory.repository import (
    DeviceRepository,
    apply_migrations,
    connect,
)
from core.inventory.whitelist import WhitelistEntry, WhitelistRepository


def _fresh_conn():
    conn = connect(":memory:")
    apply_migrations(conn)
    return conn


class DeviceModelTests(unittest.TestCase):
    def test_frozen(self):
        now = datetime.now(UTC)
        d = Device(identifier="10.0.0.1", first_seen=now, last_seen=now)
        with self.assertRaises(FrozenInstanceError):
            d.identifier = "x"

    def test_identifier_pflicht(self):
        with self.assertRaises(ValueError):
            Device(identifier="")

    def test_naive_zeit_verboten(self):
        naive = datetime(2026, 1, 1)  # noqa: DTZ001 - absichtlich naiv (Negativtest)
        with self.assertRaises(ValueError):
            Device(identifier="x", first_seen=naive)

    def test_to_dict(self):
        now = datetime.now(UTC)
        d = Device(
            identifier="10.0.0.1",
            entity_name="Server",
            network_type="Hauptnetz",
            first_seen=now,
            last_seen=now,
            device_type=DeviceType.SERVER,
        )
        out = d.to_dict()
        self.assertEqual(out["identifier"], "10.0.0.1")
        self.assertEqual(out["device_type"], "server")
        self.assertTrue(out["first_seen"].endswith("+00:00"))
        self.assertIsNone(out["id"])


class DeviceRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.conn = _fresh_conn()
        self.repo = DeviceRepository(self.conn)

    def test_upsert_seen_neu(self):
        d = self.repo.upsert_seen(
            "192.168.178.87",
            entity_name="Ghxst-Server",
            network_type="Hauptnetz",
            data={"source": "test"},
        )
        self.assertIsNotNone(d.id)
        self.assertEqual(d.identifier, "192.168.178.87")
        self.assertEqual(d.entity_name, "Ghxst-Server")
        self.assertEqual(self.repo.count(), 1)
        h = self.repo.history("192.168.178.87")
        self.assertEqual(len(h), 1)
        self.assertEqual(h[0]["event_type"], "device_seen")
        self.assertEqual(h[0]["data"], {"source": "test"})

    def test_upsert_seen_aktualisiert_last_seen_behaelt_first_seen(self):
        d1 = self.repo.upsert_seen("192.168.178.87", entity_name="A")
        later = datetime.now(UTC) + timedelta(seconds=5)
        d2 = self.repo.upsert_seen("192.168.178.87", timestamp=later)
        self.assertEqual(d2.first_seen, d1.first_seen)
        self.assertGreaterEqual(d2.last_seen, d1.last_seen)
        self.assertEqual(d2.entity_name, "A")  # nicht ueberschrieben

    def test_upsert_seen_ueberschreibt_nur_was_gesetzt_ist(self):
        self.repo.upsert_seen(
            "192.168.178.87", entity_name="Alt", network_type="Hauptnetz",
        )
        d = self.repo.upsert_seen("192.168.178.87", entity_name="Neu")
        self.assertEqual(d.entity_name, "Neu")
        self.assertEqual(d.network_type, "Hauptnetz")  # bleibt

    def test_upsert_seen_empty_ip_does_not_overwrite(self):
        """ip='' ueberschreibt last_ip nicht (Auflage 1757/1759)."""
        self.repo.upsert_seen("192.168.178.87", ip="192.168.178.87")
        d = self.repo.upsert_seen("192.168.178.87", ip="")
        self.assertEqual(d.last_ip, "192.168.178.87")

    def test_upsert_seen_none_ip_does_not_overwrite(self):
        """ip=None ueberschreibt last_ip nicht."""
        self.repo.upsert_seen("192.168.178.88", ip="192.168.178.88")
        d = self.repo.upsert_seen("192.168.178.88", ip=None)
        self.assertEqual(d.last_ip, "192.168.178.88")

    def test_from_row_with_internal_name(self):
        """from_row liest internal_name (Punkt 75)."""
        self.repo.set_internal_name("192.168.178.99", "Test-Server")
        d = self.repo.get("192.168.178.99")
        if d is None:
            # Geraet existiert nicht, wir legen es an und setzen danach.
            self.repo.upsert_seen("192.168.178.99")
            self.repo.set_internal_name("192.168.178.99", "Test-Server")
            d = self.repo.get("192.168.178.99")
        self.assertIsNotNone(d)
        self.assertEqual(d.internal_name, "Test-Server")

    def test_set_internal_name_none_deletes(self):
        """set_internal_name(None) loescht den Wert."""
        self.repo.upsert_seen("192.168.178.100")
        self.repo.set_internal_name("192.168.178.100", "Kamera")
        self.repo.set_internal_name("192.168.178.100", None)
        d = self.repo.get("192.168.178.100")
        self.assertIsNotNone(d)
        self.assertIsNone(d.internal_name)

    def test_upsert_seen_fallback_sentinel_resets_entity_name(self):
        """Sentinel ueberschreibt alten Fallback-Namen mit None (67a)."""
        from core.inventory.repository import _FALLBACK_SENTINEL
        self.repo.upsert_seen("192.168.178.90",
                              entity_name="PC-192-168-178-90")
        d = self.repo.upsert_seen("192.168.178.90",
                                  entity_name=_FALLBACK_SENTINEL)
        self.assertIsNone(d.entity_name)

    def test_upsert_seen_fallback_sentinel_from_none(self):
        """Sentinel bei existing=None laesst entity_name None."""
        from core.inventory.repository import _FALLBACK_SENTINEL
        self.repo.upsert_seen("192.168.178.91",
                              entity_name=_FALLBACK_SENTINEL)
        d = self.repo.upsert_seen("192.168.178.91",
                                  entity_name=_FALLBACK_SENTINEL)
        self.assertIsNone(d.entity_name)

    def test_upsert_seen_real_name_overwrites_fallback(self):
        """Echter Name ueberschreibt alten Fallback-Namen."""
        self.repo.upsert_seen("192.168.178.92",
                              entity_name="PC-192-168-178-92")
        d = self.repo.upsert_seen("192.168.178.92", entity_name="kamera")
        self.assertEqual(d.entity_name, "kamera")

    def test_upsert_seen_fallback_sentinel_insert_only(self):
        """INSERT-Zweig filtert Sentinel -> None (Auflage 1772)."""
        from core.inventory.repository import _FALLBACK_SENTINEL
        d = self.repo.upsert_seen("192.168.178.93",
                                  entity_name=_FALLBACK_SENTINEL)
        self.assertIsNone(d.entity_name)
        row = self.conn.execute(
            "SELECT entity_name FROM devices WHERE identifier = ?",
            ("192.168.178.93",),
        ).fetchone()
        self.assertIsNone(row[0])

    def test_upsert_seen_real_name_insert(self):
        """INSERT-Zweig speichert echten Namen (Auflage 1772)."""
        d = self.repo.upsert_seen("192.168.178.94",
                                  entity_name="kamera")
        self.assertEqual(d.entity_name, "kamera")

    def test_mark_offline(self):
        self.repo.upsert_seen("192.168.178.87", network_type="Hauptnetz")
        self.assertTrue(self.repo.mark_offline("192.168.178.87"))
        h = self.repo.history("192.168.178.87")
        self.assertEqual(h[0]["event_type"], "device_offline")
        # last_seen unveraendert (kein Update)
        d = self.repo.get("192.168.178.87")
        self.assertIsNotNone(d)

    def test_mark_offline_unbekannt(self):
        self.assertFalse(self.repo.mark_offline("10.0.0.99"))

    def test_get_und_list_all(self):
        self.repo.upsert_seen("10.0.0.1")
        self.repo.upsert_seen("10.0.0.2")
        self.assertIsNone(self.repo.get("10.0.0.99"))
        self.assertEqual(len(self.repo.list_all()), 2)

    def test_record_history_generisch(self):
        self.repo.upsert_seen("10.0.0.1")
        ok = self.repo.record_history(
            "10.0.0.1", "whitelist_added", data={"added_by": "admin"},
        )
        self.assertTrue(ok)
        h = self.repo.history("10.0.0.1")
        self.assertEqual(h[0]["event_type"], "whitelist_added")
        self.assertEqual(h[0]["data"], {"added_by": "admin"})

    def test_history_limit(self):
        for i in range(5):
            self.repo.upsert_seen("10.0.0.1", timestamp=datetime.now(UTC))
        h = self.repo.history("10.0.0.1", limit=2)
        self.assertEqual(len(h), 2)

    def test_history_unbekannt(self):
        self.assertEqual(self.repo.history("10.0.0.99"), [])

    def test_migrations_idempotent(self):
        apply_migrations(self.conn)
        apply_migrations(self.conn)
        self.assertEqual(self.repo.count(), 0)


class WhitelistRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.conn = _fresh_conn()
        self.repo = DeviceRepository(self.conn)
        self.wl = WhitelistRepository(self.conn)

    def test_leer(self):
        self.assertFalse(self.wl.is_whitelisted("192.168.178.87"))
        self.assertEqual(self.wl.count(), 0)
        self.assertEqual(self.wl.identifiers(), set())

    def test_add(self):
        e = self.wl.add("192.168.178.87", "Ghxst-Server", added_by="admin")
        self.assertIsInstance(e, WhitelistEntry)
        self.assertEqual(e.identifier, "192.168.178.87")
        self.assertEqual(e.added_by, "admin")
        self.assertTrue(self.wl.is_whitelisted("192.168.178.87"))
        self.assertEqual(self.wl.count(), 1)

    def test_add_idempotent(self):
        e1 = self.wl.add("192.168.178.87", "A", added_by="admin")
        e2 = self.wl.add("192.168.178.87", "B", added_by="admin")
        self.assertEqual(e1.id, e2.id)
        self.assertEqual(e2.entity_name, "A")
        self.assertEqual(self.wl.count(), 1)

    def test_remove(self):
        self.wl.add("192.168.178.87", "X", added_by="admin")
        self.assertTrue(self.wl.remove("192.168.178.87", removed_by="admin"))
        self.assertFalse(self.wl.is_whitelisted("192.168.178.87"))
        self.assertFalse(self.wl.remove("192.168.178.87"))

    def test_identifiers(self):
        self.wl.add("10.0.0.1", "A")
        self.wl.add("10.0.0.2", "B")
        self.assertEqual(self.wl.identifiers(), {"10.0.0.1", "10.0.0.2"})

    def test_add_schreibt_history_wenn_geraet_existiert(self):
        self.repo.upsert_seen("192.168.178.10", entity_name="Laptop",
                              network_type="Hauptnetz")
        self.wl.add("192.168.178.10", "Laptop", added_by="admin")
        h = self.repo.history("192.168.178.10")
        types = [x["event_type"] for x in h]
        self.assertIn("whitelist_added", types)
        added = next(x for x in h if x["event_type"] == "whitelist_added")
        self.assertEqual(added["data"], {"added_by": "admin"})

    def test_add_ohne_geraet_schreibt_keine_history(self):
        self.wl.add("10.0.0.99", "Unbekannt", added_by="admin")
        self.assertTrue(self.wl.is_whitelisted("10.0.0.99"))
        # Kein Geraet in devices -> keine History-Zeile
        self.assertEqual(self.repo.history("10.0.0.99"), [])

    def test_remove_schreibt_history_wenn_geraet_existiert(self):
        self.repo.upsert_seen("192.168.178.10", entity_name="Laptop")
        self.wl.add("192.168.178.10", "Laptop", added_by="admin")
        self.wl.remove("192.168.178.10", removed_by="admin")
        h = self.repo.history("192.168.178.10")
        types = [x["event_type"] for x in h]
        self.assertIn("whitelist_removed", types)


class UpsertSeenLastIpTests(unittest.TestCase):
    """Punkt 48: last_ip in upsert_seen."""

    def setUp(self):
        self.conn = _fresh_conn()
        self.repo = DeviceRepository(self.conn)

    def test_upsert_seen_with_ip_sets_last_ip(self):
        d = self.repo.upsert_seen(
            "aa:bb:cc:dd:ee:01",
            entity_name="kamera",
            network_type="Hauptnetz",
            ip="10.0.0.5",
        )
        self.assertEqual(d.last_ip, "10.0.0.5")

    def test_upsert_seen_without_ip_preserves_last_ip(self):
        self.repo.upsert_seen(
            "aa:bb:cc:dd:ee:02",
            entity_name="kamera",
            ip="10.0.0.5",
        )
        d2 = self.repo.upsert_seen(
            "aa:bb:cc:dd:ee:02",
            entity_name="kamera",
        )
        self.assertEqual(d2.last_ip, "10.0.0.5")

    def test_upsert_seen_without_ip_first_time(self):
        d = self.repo.upsert_seen(
            "aa:bb:cc:dd:ee:03",
            entity_name="kamera",
        )
        self.assertIsNone(d.last_ip)

    def test_upsert_seen_new_ip_overwrites(self):
        self.repo.upsert_seen(
            "aa:bb:cc:dd:ee:04", ip="10.0.0.5",
        )
        d2 = self.repo.upsert_seen(
            "aa:bb:cc:dd:ee:04", ip="10.0.0.6",
        )
        self.assertEqual(d2.last_ip, "10.0.0.6")


if __name__ == "__main__":
    unittest.main()
