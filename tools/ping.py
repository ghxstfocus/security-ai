# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tool: ping (Punkt 58 Runde 1, Schritt 2).

Pingt ein Ziel im autorisierten Netz. Fail closed:
Ziel ausserhalb scope -> ToolError. subprocess mit
shell=False, Timeout 10s, check=False.

Signatur folgt dem AgentLoop: tool.func(**args).
Also: ping_run(target=..., count=...).
"""
from __future__ import annotations

import subprocess
from typing import Any

from core.net.scope import check_target_allowed
from harness.tool_registry.tool import ToolError

_PING_TIMEOUT_S = 10
_COUNT_MIN = 1
_COUNT_MAX = 10

def ping_run(target: str, count: int = 4) -> dict[str, Any]:
    """
    Pingt ein Ziel im autorisierten Netz.

    Fail closed: Ziel ausserhalb scope, ungueltiges count,
    Timeout -> ToolError.
    """
    if not isinstance(target, str):
        raise ToolError(
            f"ping: 'target' muss String sein, "
            f"nicht {type(target).__name__}"
        )
    t = target.strip()
    if not t:
        raise ToolError("ping: 'target' darf nicht leer sein")
    if not isinstance(count, int) or isinstance(count, bool):
        raise ToolError("ping: 'count' muss int sein")
    if count < _COUNT_MIN or count > _COUNT_MAX:
        raise ToolError(
            f"ping: 'count' muss {_COUNT_MIN}..{_COUNT_MAX} sein"
        )
    check_target_allowed(t)
    argv = ["ping", "-c", str(count), "-W", "1", t]
    try:
        proc = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=_PING_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"ping: Timeout nach {_PING_TIMEOUT_S}s") from exc
    except FileNotFoundError as exc:
        raise ToolError("ping: 'ping' nicht im PATH") from exc
    except OSError as exc:
        raise ToolError(f"ping: OSError: {exc}") from exc
    return {
        "target": t,
        "count": count,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "source": "ping",
    }

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool

PING_TOOL = Tool(
    name="ping",
    level=Level.READ,
    func=ping_run,
    description="Pingt ein Ziel im autorisierten Netz.",
    version="0.1.0",
    sandbox_profile="net_diag_local",
    allowed_args=frozenset({"target", "count"}),
    returns="dict",
)

__all__ = [
    "PING_TOOL",
    "ping_run",
]
