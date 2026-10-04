# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tool: whois (Punkt 58 Runde 1, Schritt 3, Tool 4).

whois-Abfrage gegen ein Ziel im autorisierten Netz.
Fail closed: Ziel ausserhalb scope -> ToolError.
subprocess mit shell=False, Timeout 10s, check=False.

Hinweis: whois gegen externe Ziele ist nicht erlaubt.
Wenn der Nutzer WHOIS-Abfragen gegen externe IPs will:
eigener Punkt, eigene Ausnahme (scope_guard erweitern).

Signatur folgt dem AgentLoop: tool.func(**args).
Also: whois_run(target=...).
"""
from __future__ import annotations

import subprocess
from typing import Any

from core.net.scope import check_target_allowed
from harness.tool_registry.tool import ToolError

_TIMEOUT_S = 10

def whois_run(target: str) -> dict[str, Any]:
    """
    whois-Abfrage gegen ein Ziel im autorisierten Netz.

    Fail closed: Ziel ausserhalb scope, Timeout,
    Binary fehlt -> ToolError.
    """
    if not isinstance(target, str):
        raise ToolError(
            f"whois: 'target' muss String sein, "
            f"nicht {type(target).__name__}"
        )
    t = target.strip()
    if not t:
        raise ToolError("whois: 'target' darf nicht leer sein")
    check_target_allowed(t)
    argv = ["whois", "--", t]
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
        raise ToolError(f"whois: Timeout nach {_TIMEOUT_S}s") from exc
    except FileNotFoundError as exc:
        raise ToolError(
            "whois: Binary nicht installiert (apt install whois)"
        ) from exc
    except OSError as exc:
        raise ToolError(f"whois: OSError: {exc}") from exc
    return {
        "target": t,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "source": "whois",
    }

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool

WHOIS_TOOL = Tool(
    name="whois",
    level=Level.READ,
    func=whois_run,
    description="whois-Abfrage gegen ein Ziel im autorisierten Netz.",
    version="0.1.0",
    sandbox_profile="net_diag_local",
    allowed_args=frozenset({"target"}),
    returns="dict",
)

__all__ = [
    "WHOIS_TOOL",
    "whois_run",
]
