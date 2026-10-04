# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer net_diag-Tools (Punkt 58 Runde 1, Schritt 2)."""
from __future__ import annotations

import unittest
from unittest import mock

from harness.tool_registry.tool import ToolError
from tools.disk_usage import disk_usage_run
from tools.dns_lookup import dns_lookup_run
from tools.ping import ping_run
from tools.port_check import port_check_run
from tools.service_status import service_status_run
from tools.system_status import system_status_run
from tools.traceroute import traceroute_run
from tools.whois import whois_run


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


class DnsLookupTests(unittest.TestCase):
    def test_dns_lookup_localhost(self) -> None:
        result = dns_lookup_run(hostname="localhost")
        self.assertEqual(result["hostname"], "localhost")
        self.assertIn("127.0.0.1", result["addresses"])
        self.assertEqual(result["source"], "dns_lookup")

    def test_dns_lookup_invalid_hostname(self) -> None:
        with self.assertRaises(ToolError):
            dns_lookup_run(hostname="8.8.8.8;rm")

    def test_dns_lookup_empty_hostname(self) -> None:
        with self.assertRaises(ToolError):
            dns_lookup_run(hostname="")


class PortCheckTests(unittest.TestCase):
    def test_port_check_open(self) -> None:
        sock = mock.MagicMock()
        sock.__enter__ = mock.MagicMock(return_value=sock)
        sock.__exit__ = mock.MagicMock(return_value=False)
        sock.connect_ex = mock.MagicMock(return_value=0)
        with mock.patch("tools.port_check.socket.socket", return_value=sock):
            result = port_check_run(target="127.0.0.1", port=443)
        self.assertTrue(result["open"])
        self.assertEqual(result["port"], 443)
        self.assertEqual(result["source"], "port_check")

    def test_port_check_closed(self) -> None:
        sock = mock.MagicMock()
        sock.__enter__ = mock.MagicMock(return_value=sock)
        sock.__exit__ = mock.MagicMock(return_value=False)
        sock.connect_ex = mock.MagicMock(return_value=111)
        with mock.patch("tools.port_check.socket.socket", return_value=sock):
            result = port_check_run(target="127.0.0.1", port=1)
        self.assertFalse(result["open"])

    def test_port_check_invalid_port(self) -> None:
        with self.assertRaises(ToolError):
            port_check_run(target="127.0.0.1", port=0)
        with self.assertRaises(ToolError):
            port_check_run(target="127.0.0.1", port=65536)

    def test_port_check_invalid_timeout(self) -> None:
        with self.assertRaises(ToolError):
            port_check_run(target="127.0.0.1", port=443, timeout=0.1)
        with self.assertRaises(ToolError):
            port_check_run(target="127.0.0.1", port=443, timeout=11.0)

    def test_port_check_out_of_scope_denied(self) -> None:
        with self.assertRaises(ToolError):
            port_check_run(target="8.8.8.8", port=443)


class WhoisTests(unittest.TestCase):
    def test_whois_in_scope(self) -> None:
        fake = mock.Mock(returncode=0, stdout="WHOIS ok", stderr="")
        with mock.patch("tools.whois.subprocess.run", return_value=fake):
            result = whois_run(target="127.0.0.1")
        self.assertEqual(result["target"], "127.0.0.1")
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["source"], "whois")
        self.assertIn("WHOIS ok", result["stdout"])

    def test_whois_out_of_scope_denied(self) -> None:
        with self.assertRaises(ToolError):
            whois_run(target="8.8.8.8")

    def test_whois_binary_missing(self) -> None:
        with mock.patch("tools.whois.subprocess.run", side_effect=FileNotFoundError()), self.assertRaises(ToolError):
            whois_run(target="127.0.0.1")


class SystemStatusTests(unittest.TestCase):
    def test_system_status_liefert_werte(self) -> None:
        result = system_status_run()
        self.assertIn("cpu_percent", result)
        self.assertIn("cpu_count", result)
        self.assertIn("ram_percent", result)
        self.assertIn("loadavg_1", result)
        self.assertIn("uptime_seconds", result)
        self.assertEqual(result["source"], "system_status")
        self.assertGreater(result["cpu_count"], 0)

    def test_system_status_psutil_fehler(self) -> None:
        with mock.patch("tools.system_status.psutil.virtual_memory", side_effect=RuntimeError("boom")), self.assertRaises(ToolError):
            system_status_run()


class ServiceStatusTests(unittest.TestCase):
    def test_service_status_active(self) -> None:
        fake = mock.Mock(returncode=0, stdout="active\n", stderr="")
        with mock.patch("tools.service_status.subprocess.run", return_value=fake):
            result = service_status_run(unit="security-ai-dashboard.service")
        self.assertEqual(result["unit"], "security-ai-dashboard.service")
        self.assertEqual(result["state"], "active")
        self.assertEqual(result["source"], "service_status")

    def test_service_status_unknown_unit(self) -> None:
        with self.assertRaises(ToolError):
            service_status_run(unit="apache2.service")

    def test_service_status_timeout(self) -> None:
        import subprocess as _sp
        with mock.patch("tools.service_status.subprocess.run", side_effect=_sp.TimeoutExpired(cmd="systemctl", timeout=2)), self.assertRaises(ToolError):
            service_status_run(unit="security-ai-dashboard.service")


class DiskUsageTests(unittest.TestCase):
    def test_disk_usage_root(self) -> None:
        result = disk_usage_run(mountpoint="/")
        self.assertEqual(result["mountpoint"], "/")
        self.assertGreater(result["total_bytes"], 0)
        self.assertGreater(result["used_bytes"], 0)
        self.assertGreaterEqual(result["percent"], 0.0)
        self.assertEqual(result["source"], "disk_usage")

    def test_disk_usage_invalid_mountpoint(self) -> None:
        with self.assertRaises(ToolError):
            disk_usage_run(mountpoint="kein-slash")

    def test_disk_usage_path_traversal(self) -> None:
        with self.assertRaises(ToolError):
            disk_usage_run(mountpoint="/etc/..")
