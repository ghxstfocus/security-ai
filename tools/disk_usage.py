# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tool: disk_usage (Punkt 58 Runde 1, Schritt 4, Tool 3).

Disk-Auslastung fuer einen Mountpoint via psutil.
Kein subprocess. Nur Lesen.

Signatur folgt dem AgentLoop: tool.func(**args).
Also: disk_usage_run(mountpoint=...).
"""
from __future__ import annotations

from typing import Any

import psutil

from harness.tool_registry.tool import ToolError

_MAX_MOUNTPOINT_LEN = 256

def disk_usage_run(mountpoint: str = "/") -> dict[str, Any]:
    """
    Disk-Auslastung fuer einen Mountpoint.

    Fail closed: mountpoint muss mit / beginnen,
    kein Path-Traversal, psutil-Fehler -> ToolError.
    """
    if not isinstance(mountpoint, str):
        raise ToolError("disk_usage: 'mountpoint' muss String sein")
    m = mountpoint.strip()
    if not m:
        raise ToolError("disk_usage: 'mountpoint' darf nicht leer sein")
    if not m.startswith("/"):
        raise ToolError("disk_usage: 'mountpoint' muss mit / beginnen")
    if len(m) > _MAX_MOUNTPOINT_LEN:
        raise ToolError(f"disk_usage: 'mountpoint' zu lang (> {_MAX_MOUNTPOINT_LEN})")
    if ".." in m:
        raise ToolError("disk_usage: 'mountpoint' darf kein .. enthalten")
    try:
        du = psutil.disk_usage(m)
    except Exception as exc:
        raise ToolError(f"disk_usage: psutil-Fehler fuer {m!r}: {exc}") from exc
    return {
        "mountpoint": m,
        "total_bytes": int(du.total),
        "used_bytes": int(du.used),
        "free_bytes": int(du.free),
        "percent": float(du.percent),
        "source": "disk_usage",
    }

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool

DISK_USAGE_TOOL = Tool(
    name="disk_usage",
    level=Level.READ,
    func=disk_usage_run,
    description="Disk-Auslastung fuer einen Mountpoint.",
    version="0.1.0",
    sandbox_profile="read_only",
    allowed_args=frozenset({"mountpoint"}),
    returns="dict",
)

__all__ = [
    "DISK_USAGE_TOOL",
    "disk_usage_run",
]
