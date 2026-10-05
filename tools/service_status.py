# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tool: service_status (Punkt 58 Runde 1, Schritt 4, Tool 2).

Systemctl is-active fuer eine Unit aus der Whitelist.
Fail closed: Unit ausserhalb Whitelist -> ToolError.
Ausnahme Paragraph N (Punkt 66): Argument-Whitelist,
shell=False, timeout=2, check=False.

Signatur folgt dem AgentLoop: tool.func(**args).
Also: service_status_run(unit=...).
"""
from __future__ import annotations

import subprocess
from typing import Any

from core.services.system_status_service import (
    UNIT_WHITELIST,
)
from harness.tool_registry.tool import (
    ToolArgumentValueError,
    ToolError,
)

_SYSTEMCTL_BIN = "systemctl"
_TIMEOUT_S = 2

def service_status_run(unit: str) -> dict[str, Any]:
    """
    is-active fuer eine Unit aus der Whitelist.

    Fail closed: Unit nicht in Whitelist, Timeout,
    Binary fehlt -> ToolError.
    """
    if not isinstance(unit, str):
        raise ToolArgumentValueError("service_status: 'unit' muss String sein")
    u = unit.strip()
    if not u:
        raise ToolArgumentValueError("service_status: 'unit' darf nicht leer sein")
    if u not in UNIT_WHITELIST:
        raise ToolArgumentValueError(
            f"service_status: Unit {u!r} nicht in Whitelist"
        )
    argv = [_SYSTEMCTL_BIN, "is-active", u]
    try:
        proc = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"service_status: Timeout nach {_TIMEOUT_S}s") from exc
    except FileNotFoundError as exc:
        raise ToolError("service_status: 'systemctl' nicht im PATH") from exc
    except OSError as exc:
        raise ToolError(f"service_status: OSError: {exc}") from exc
    state = (proc.stdout or "").strip() or "unknown"
    return {
        "unit": u,
        "state": state,
        "returncode": proc.returncode,
        "source": "service_status",
    }

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool

SERVICE_STATUS_TOOL = Tool(
    name="service_status",
    level=Level.READ,
    func=service_status_run,
    description="is-active fuer eine Unit aus der Whitelist.",
    version="0.1.0",
    sandbox_profile="read_only",
    allowed_args=frozenset({"unit"}),
    returns="dict",
)

__all__ = [
    "SERVICE_STATUS_TOOL",
    "service_status_run",
]
