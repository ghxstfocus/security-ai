# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer net_diag-Tools (Punkt 58 Runde 1, Schritt 2)."""
from __future__ import annotations

import unittest
from unittest import mock

from harness.tool_registry.tool import ToolError
from tools.ping import ping_run
from tools.traceroute import traceroute_run


class PingTests(unittest.TestCase):
    def test_ping_in_scope(self) -> None:
        fake = mock.Mock(returncode=0, stdout="PING ok", stderr="")
        with mock.patch("tools.ping.subprocess.run", return_value=fake):
            result = ping_run(target="127.0.0.1", count=2)
        self.assertEqual(result["target"], "127.0.0.1")
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["source"], "ping")
        self.assertIn("PING ok", result["stdout"])

    def test_ping_out_of_scope_denied(self) -> None:
        with self.assertRaises(ToolError):
            ping_run(target="8.8.8.8")

    def test_ping_count_invalid(self) -> None:
        with self.assertRaises(ToolError):
            ping_run(target="127.0.0.1", count=0)
        with self.assertRaises(ToolError):
            ping_run(target="127.0.0.1", count=99)

    def test_ping_target_empty(self) -> None:
        with self.assertRaises(ToolError):
            ping_run(target="")


class TracerouteTests(unittest.TestCase):
    def test_traceroute_in_scope(self) -> None:
        fake = mock.Mock(returncode=0, stdout="TRACE ok", stderr="")
        with mock.patch("tools.traceroute.subprocess.run", return_value=fake):
            result = traceroute_run(target="127.0.0.1", max_hops=5)
        self.assertEqual(result["target"], "127.0.0.1")
        self.assertEqual(result["max_hops"], 5)
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["source"], "traceroute")
        self.assertIn("TRACE ok", result["stdout"])

    def test_traceroute_out_of_scope_denied(self) -> None:
        with self.assertRaises(ToolError):
            traceroute_run(target="8.8.8.8")

    def test_traceroute_max_hops_invalid(self) -> None:
        with self.assertRaises(ToolError):
            traceroute_run(target="127.0.0.1", max_hops=0)
        with self.assertRaises(ToolError):
            traceroute_run(target="127.0.0.1", max_hops=99)
