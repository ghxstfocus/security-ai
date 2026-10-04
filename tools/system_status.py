# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tool: system_status (Punkt 58 Runde 1, Schritt 4, Tool 1).

Systemzustand via psutil: CPU, RAM, Load, Uptime.
Kein subprocess. Nur Lesen.

Signatur folgt dem AgentLoop: tool.func(**args).
Also: system_status_run().
"""
from __future__ import annotations

import time
from typing import Any

import psutil

from harness.tool_registry.tool import ToolError


def system_status_run() -> dict[str, Any]:
    """
    Liest CPU/RAM/Load/Uptime via psutil.

    Fail closed: bei psutil-Fehler -> ToolError.
    """
    try:
        cpu_percent = float(psutil.cpu_percent(interval=None))
        cpu_count = int(psutil.cpu_count() or 0)
        vm = psutil.virtual_memory()
        loadavg = psutil.getloadavg()
        uptime = int(time.time() - psutil.boot_time())
    except Exception as exc:
        raise ToolError(f"system_status: psutil-Fehler: {exc}") from exc
    return {
        "cpu_percent": cpu_percent,
        "cpu_count": cpu_count,
        "ram_percent": float(vm.percent),
        "ram_used_gb": round(vm.used / (1024 ** 3), 1),
        "ram_total_gb": round(vm.total / (1024 ** 3), 1),
        "loadavg_1": round(loadavg[0], 2),
        "loadavg_5": round(loadavg[1], 2),
        "loadavg_15": round(loadavg[2], 2),
        "uptime_seconds": uptime,
        "source": "system_status",
    }

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool

SYSTEM_STATUS_TOOL = Tool(
    name="system_status",
    level=Level.READ,
    func=system_status_run,
    description="Systemzustand (CPU, RAM, Load, Uptime).",
    version="0.1.0",
    sandbox_profile="read_only",
    allowed_args=frozenset(),
    returns="dict",
)

__all__ = [
    "SYSTEM_STATUS_TOOL",
    "system_status_run",
]
