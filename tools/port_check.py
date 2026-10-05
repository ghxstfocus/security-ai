# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tool: port_check (Punkt 58 Runde 1, Schritt 3, Tool 3).

Prueft, ob ein TCP-Port auf einem Ziel im autorisierten
Netz offen ist. Kein subprocess, Python socket.
Fail closed: Ziel ausserhalb scope, ungueltiger port,
ungueltiger timeout -> ToolError.

Signatur folgt dem AgentLoop: tool.func(**args).
Also: port_check_run(target=..., port=..., timeout=...).
"""
from __future__ import annotations

import socket
from typing import Any

from core.net.scope import check_target_allowed
from harness.tool_registry.tool import (
    ToolArgumentValueError,
    ToolError,
)

_PORT_MIN = 1
_PORT_MAX = 65535
_TIMEOUT_MIN = 0.5
_TIMEOUT_MAX = 10.0

def port_check_run(target: str, port: int, timeout: float = 2.0) -> dict[str, Any]:
    """
    Prueft, ob ein TCP-Port offen ist.

    Fail closed: Scope, port 1..65535, timeout 0.5..10.0,
    OSError -> ToolError.
    """
    if not isinstance(target, str):
        raise ToolArgumentValueError(
            f"port_check: 'target' muss String sein, "
            f"nicht {type(target).__name__}"
        )
    t = target.strip()
    if not t:
        raise ToolArgumentValueError("port_check: 'target' darf nicht leer sein")
    if not isinstance(port, int) or isinstance(port, bool):
        raise ToolArgumentValueError("port_check: 'port' muss int sein")
    if port < _PORT_MIN or port > _PORT_MAX:
        raise ToolArgumentValueError(
            f"port_check: 'port' muss {_PORT_MIN}..{_PORT_MAX} sein"
        )
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        raise ToolArgumentValueError("port_check: 'timeout' muss Zahl sein")
    if timeout < _TIMEOUT_MIN or timeout > _TIMEOUT_MAX:
        raise ToolArgumentValueError(
            f"port_check: 'timeout' muss {_TIMEOUT_MIN}..{_TIMEOUT_MAX} sein"
        )
    check_target_allowed(t)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(float(timeout))
            result = sock.connect_ex((t, port))
    except OSError as exc:
        raise ToolError(f"port_check: OSError: {exc}") from exc
    return {
        "target": t,
        "port": port,
        "open": result == 0,
        "source": "port_check",
    }

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool

PORT_CHECK_TOOL = Tool(
    name="port_check",
    level=Level.READ,
    func=port_check_run,
    description="Prueft, ob ein TCP-Port offen ist.",
    version="0.1.0",
    sandbox_profile="net_diag_local",
    allowed_args=frozenset({"target", "port", "timeout"}),
    returns="dict",
)

__all__ = [
    "PORT_CHECK_TOOL",
    "port_check_run",
]
