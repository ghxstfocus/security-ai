# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tool: traceroute (Punkt 58 Runde 1, Schritt 3, Tool 1).

Traceroute gegen ein Ziel im autorisierten Netz. Fail closed:
Ziel ausserhalb scope -> ToolError. subprocess mit
shell=False, Timeout 15s, check=False.

Signatur folgt dem AgentLoop: tool.func(**args).
Also: traceroute_run(target=..., max_hops=...).
"""
from __future__ import annotations

import subprocess
from typing import Any

from core.net.scope import check_target_allowed
from harness.tool_registry.tool import ToolError

_TIMEOUT_S = 15
_HOPS_MIN = 1
_HOPS_MAX = 30

def traceroute_run(target: str, max_hops: int = 30) -> dict[str, Any]:
    """
    Traceroute gegen ein Ziel im autorisierten Netz.

    Fail closed: Ziel ausserhalb scope, ungueltige max_hops,
    Timeout -> ToolError.
    """
    if not isinstance(target, str):
        raise ToolError(
            f"traceroute: 'target' muss String sein, "
            f"nicht {type(target).__name__}"
        )
    t = target.strip()
    if not t:
        raise ToolError("traceroute: 'target' darf nicht leer sein")
    if not isinstance(max_hops, int) or isinstance(max_hops, bool):
        raise ToolError("traceroute: 'max_hops' muss int sein")
    if max_hops < _HOPS_MIN or max_hops > _HOPS_MAX:
        raise ToolError(
            f"traceroute: 'max_hops' muss {_HOPS_MIN}..{_HOPS_MAX} sein"
        )
    check_target_allowed(t)
    argv = ["traceroute", "-m", str(max_hops), "--", t]
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
        raise ToolError(f"traceroute: Timeout nach {_TIMEOUT_S}s") from exc
    except FileNotFoundError as exc:
        raise ToolError("traceroute: 'traceroute' nicht im PATH") from exc
    except OSError as exc:
        raise ToolError(f"traceroute: OSError: {exc}") from exc
    return {
        "target": t,
        "max_hops": max_hops,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "source": "traceroute",
    }

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool

TRACEROUTE_TOOL = Tool(
    name="traceroute",
    level=Level.READ,
    func=traceroute_run,
    description="Traceroute gegen ein Ziel im autorisierten Netz.",
    version="0.1.0",
    sandbox_profile="net_diag_local",
    allowed_args=frozenset({"target", "max_hops"}),
    returns="dict",
)

__all__ = [
    "TRACEROUTE_TOOL",
    "traceroute_run",
]
