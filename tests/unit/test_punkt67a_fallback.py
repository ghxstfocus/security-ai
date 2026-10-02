# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests Punkt 67a: Fallback-Namen im Watcher + Repository (Kat 3)."""
from __future__ import annotations

import unittest
from unittest import mock

from tools import fritzbox_watcher as fw


class FallbackNameTests(unittest.TestCase):
    """Watcher: Fallback-Muster -> Sentinel."""

    def _run_fetch(self, name: str) -> object:
        class FakeConn:
            def __init__(self, **kw: object) -> None:
                pass

        class FakeHosts:
            def __init__(self, fc: object) -> None:
                pass

            def get_hosts_info(self) -> list:
                return [{"mac": "aa:01", "ip": "10.0.0.1",
                         "name": name, "status": True}]

        with mock.patch.object(fw, "FritzConnection", FakeConn), \
                mock.patch.object(fw, "FritzHosts", FakeHosts):
            return fw._fetch_hosts("fritz.box", "user", "pw")[0]["name"]

    def test_mac_fallback_becomes_sentinel(self) -> None:
        self.assertEqual(
            self._run_fetch("PC-82-E1-00-82-16-96"),
            fw._FALLBACK_SENTINEL,
        )

    def test_ip_fallback_becomes_sentinel(self) -> None:
        self.assertEqual(
            self._run_fetch("PC-192-168-178-117"),
            fw._FALLBACK_SENTINEL,
        )

    def test_real_name_unchanged(self) -> None:
        self.assertEqual(self._run_fetch("S25-von-A"), "S25-von-A")

    def test_missing_name_unchanged(self) -> None:
        self.assertEqual(self._run_fetch(""), "")


if __name__ == "__main__":
    unittest.main()
