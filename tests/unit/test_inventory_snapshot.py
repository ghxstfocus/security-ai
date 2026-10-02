# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer core/reporting/inventory_snapshot.py (Punkt 75)."""
from __future__ import annotations

import unittest
from datetime import UTC, datetime

from core.reporting.inventory_snapshot import build_inventory_snapshot


def _dev(ident, *, internal=None, entity=None, whitelisted=False):
    return {
        "identifier": ident,
        "internal_name": internal,
        "entity_name": entity,
        "network_type": "Hauptnetz",
        "first_seen": datetime.now(UTC).isoformat(),
        "last_seen": datetime.now(UTC).isoformat(),
    }


class NamedDevicesTests(unittest.TestCase):

    def test_named_devices_with_internal(self):
        devs = [_dev("aa:01", internal="Server-Sandra")]
        snap = build_inventory_snapshot(devs, [])
        self.assertEqual(len(snap["named_devices"]), 1)
        self.assertEqual(snap["named_devices"][0]["name"], "Server-Sandra")

    def test_named_devices_fallback(self):
        # internal_name None -> entity_name.
        devs = [_dev("aa:02", entity="Fritz!Box-Keller")]
        snap = build_inventory_snapshot(devs, [])
        self.assertEqual(snap["named_devices"][0]["name"], "Fritz!Box-Keller")
        # beide None -> identifier.
        devs2 = [_dev("aa:03")]
        snap2 = build_inventory_snapshot(devs2, [])
        self.assertEqual(snap2["named_devices"][0]["name"], "aa:03")

    def test_named_devices_whitelisted_flag(self):
        devs = [_dev("aa:04", internal="Kamera")]
        snap = build_inventory_snapshot(devs, ["aa:04"])
        self.assertTrue(snap["named_devices"][0]["whitelisted"])

    def test_bestehende_felder_unveraendert(self):
        devs = [_dev("aa:05", internal="X")]
        snap = build_inventory_snapshot(devs, [])
        for k in ("device_count", "whitelist_count",
                  "devices_online", "devices_offline",
                  "recently_added", "recently_offline"):
            self.assertIn(k, snap)


if __name__ == "__main__":
    unittest.main()
