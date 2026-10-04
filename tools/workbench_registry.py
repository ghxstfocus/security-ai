# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Werkbank-Registry (Punkt 58, Runde 1).

Enthaelt nur Level 0-1 read-only Tools. Zweite
Registry neben der Orchestrator-Registry
(apps/security_ai/orchestrator.py). Kein AgentLoop-Pfad.

Verwendung:

    from tools.workbench_registry import build_workbench_registry
    registry = build_workbench_registry()

Siehe WEB_SECURITY_CHECKLIST §N-Ausnahme Werkbank.
"""
from __future__ import annotations

from harness.tool_registry.registry import ToolRegistry
from tools.audit_tail import AUDIT_TAIL_TOOL
from tools.device_history import DEVICE_HISTORY_TOOL
from tools.disk_usage import DISK_USAGE_TOOL
from tools.dns_lookup import DNS_LOOKUP_TOOL
from tools.event_tail import EVENT_TAIL_TOOL
from tools.network_interfaces import NETWORK_INTERFACES_TOOL
from tools.ping import PING_TOOL
from tools.port_check import PORT_CHECK_TOOL
from tools.scan_history import SCAN_HISTORY_TOOL
from tools.service_status import SERVICE_STATUS_TOOL
from tools.system_status import SYSTEM_STATUS_TOOL
from tools.traceroute import TRACEROUTE_TOOL
from tools.whois import WHOIS_TOOL


def build_workbench_registry() -> ToolRegistry:
    """Baut die Werkbank-Registry mit 13 Level-0-1-Tools.

    Kein Import aus apps/security_ai/orchestrator.
    Kein Import aus core/.
    """
    reg = ToolRegistry()
    reg.register(PING_TOOL)
    reg.register(TRACEROUTE_TOOL)
    reg.register(WHOIS_TOOL)
    reg.register(DNS_LOOKUP_TOOL)
    reg.register(PORT_CHECK_TOOL)
    reg.register(SYSTEM_STATUS_TOOL)
    reg.register(SERVICE_STATUS_TOOL)
    reg.register(DISK_USAGE_TOOL)
    reg.register(NETWORK_INTERFACES_TOOL)
    reg.register(AUDIT_TAIL_TOOL)
    reg.register(EVENT_TAIL_TOOL)
    reg.register(DEVICE_HISTORY_TOOL)
    reg.register(SCAN_HISTORY_TOOL)
    return reg


__all__ = [
    "build_workbench_registry",
]
