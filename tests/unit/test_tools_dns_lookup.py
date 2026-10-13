# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer tools/dns_lookup.py (Auflage 2000)."""
from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

from harness.tool_registry.tool import ToolError
from tools.dns_lookup import dns_lookup_run


class DnsLookupScopeTests(unittest.TestCase):
    def test_dns_lookup_rejects_target_outside_scope(self) -> None:
        with self.assertRaises(ToolError):
            dns_lookup_run("8.8.8.8")

    def test_dns_lookup_allows_target_inside_scope(self) -> None:
        fake_infos = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("192.168.178.1", 0),
            ),
        ]
        with patch(
            "tools.dns_lookup.socket.getaddrinfo",
            return_value=fake_infos,
        ):
            result = dns_lookup_run("192.168.178.1")
        self.assertEqual(result["hostname"], "192.168.178.1")
        self.assertEqual(result["addresses"], ["192.168.178.1"])
        self.assertEqual(result["source"], "dns_lookup")

    def test_dns_lookup_raises_tool_error_on_dns_failure(self) -> None:
        with patch(
            "tools.dns_lookup.socket.getaddrinfo",
            side_effect=socket.gaierror("fake dns failure"),
        ), self.assertRaises(ToolError) as ctx:
            dns_lookup_run("192.168.178.1")
        self.assertIn("DNS-Fehler", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
