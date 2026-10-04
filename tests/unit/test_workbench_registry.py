# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer die Werkbank-Registry (Punkt 58, Auflage 1988)."""
from __future__ import annotations

import unittest

from harness.permissions.levels import Level
from tools.workbench_registry import build_workbench_registry

EXPECTED_TOOLS = frozenset({
    "ping",
    "traceroute",
    "whois",
    "dns_lookup",
    "port_check",
    "system_status",
    "service_status",
    "disk_usage",
    "network_interfaces",
    "audit_tail",
    "event_tail",
    "device_history",
    "scan_history",
})

ALLOWED_SANDBOX_PROFILES = frozenset({
    "net_diag_local",
    "read_only",
})


class WorkbenchRegistryTests(unittest.TestCase):
    def test_registry_contains_expected_tool_names(self) -> None:
        reg = build_workbench_registry()
        self.assertEqual(set(reg.list_names()), EXPECTED_TOOLS)

    def test_all_tools_have_read_level(self) -> None:
        reg = build_workbench_registry()
        for tool in reg.list_tools():
            self.assertLessEqual(
                tool.level, Level.READ,
                f"Tool {tool.name} hat Level {tool.level}, "
                f"Werkbank erlaubt nur Level <= READ",
            )

    def test_no_tool_above_read_level(self) -> None:
        reg = build_workbench_registry()
        hoch = [t.name for t in reg.list_tools()
                if t.level > Level.READ]
        self.assertEqual(
            hoch, [],
            f"Werkbank-Tools mit Level > READ: {hoch}",
        )

    def test_all_tools_have_known_sandbox_profile(self) -> None:
        reg = build_workbench_registry()
        for tool in reg.list_tools():
            self.assertIn(
                tool.sandbox_profile, ALLOWED_SANDBOX_PROFILES,
                f"Tool {tool.name} hat unbekanntes "
                f"sandbox_profile: {tool.sandbox_profile}",
            )


if __name__ == "__main__":
    unittest.main()
