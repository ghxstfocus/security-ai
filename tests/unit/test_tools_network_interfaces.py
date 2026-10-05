# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer tools/network_interfaces.py (Auflage 2010)."""
from __future__ import annotations

import socket
import types
import unittest
from unittest.mock import patch

from harness.tool_registry.tool import ToolError
from tools.network_interfaces import network_interfaces_run


def _fake_snicaddr(family, address):
    """Baut ein snicaddr-aehnliches Objekt (Attributzugriff)."""
    return types.SimpleNamespace(
        family=family,
        address=address,
        netmask=None,
        broadcast=None,
        ptp=None,
    )


class NetworkInterfacesTests(unittest.TestCase):

    def test_network_interfaces_handles_af_inet6_unsupported(
        self,
    ) -> None:
        err = OSError(97, "Address family not supported by protocol")
        with patch(
            "tools.network_interfaces.psutil.net_if_addrs",
            side_effect=err,
        ), patch(
            "tools.network_interfaces.psutil.net_if_stats",
            return_value={"lo": None, "eth0": None},
        ):
            result = network_interfaces_run()
        self.assertIn("interfaces", result)
        self.assertIn("lo", result["interfaces"])
        self.assertIn("eth0", result["interfaces"])
        self.assertEqual(
            result["interfaces"]["lo"]["addresses"], [],
        )
        self.assertTrue(result["ipv4_only"])

    def test_network_interfaces_returns_ipv4_only(self) -> None:
        fake = {
            "lo": [
                _fake_snicaddr(socket.AF_INET, "127.0.0.1"),
            ],
            "eth0": [
                _fake_snicaddr(socket.AF_INET, "192.168.178.117"),
                _fake_snicaddr(socket.AF_INET6, "fe80::1"),
            ],
        }
        with patch(
            "tools.network_interfaces.psutil.net_if_addrs",
            return_value=fake,
        ):
            result = network_interfaces_run()
        self.assertFalse(result["ipv4_only"])
        self.assertEqual(
            len(result["interfaces"]["lo"]["addresses"]), 1,
        )
        self.assertEqual(
            len(result["interfaces"]["eth0"]["addresses"]), 2,
        )

    def test_network_interfaces_raises_on_total_failure(self) -> None:
        with patch(
            "tools.network_interfaces.psutil.net_if_addrs",
            side_effect=RuntimeError("kaputt"),
        ), self.assertRaises(ToolError):
            network_interfaces_run()


if __name__ == "__main__":
    unittest.main()
