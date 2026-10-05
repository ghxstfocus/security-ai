# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tool: dns_lookup (Punkt 58 Runde 1, Schritt 3, Tool 2).

DNS-Aufloesung eines Hostnames. Kein subprocess,
Python socket.getaddrinfo. Scope-Check via
check_target_allowed (Auflage 2000): DNS-Aufloesung
selbst ist harmlos, aber einheitliches Muster fuer
alle net_diag-Tools.

Signatur folgt dem AgentLoop: tool.func(**args).
Also: dns_lookup_run(hostname=...).
"""
from __future__ import annotations

import re
import socket
from typing import Any

from core.net.scope import check_target_allowed
from harness.tool_registry.tool import ToolError

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.-]+$")
_HOSTNAME_MIN = 1
_HOSTNAME_MAX = 253

def dns_lookup_run(hostname: str) -> dict[str, Any]:
    """
    Loest einen Hostnamen auf (IPv4 + IPv6).

    Fail closed: ungueltiger hostname, DNS-Fehler,
    OSError -> ToolError.
    """
    if not isinstance(hostname, str):
        raise ToolError(
            f"dns_lookup: 'hostname' muss String sein, "
            f"nicht {type(hostname).__name__}"
        )
    h = hostname.strip()
    if not h:
        raise ToolError("dns_lookup: 'hostname' darf nicht leer sein")
    if len(h) < _HOSTNAME_MIN or len(h) > _HOSTNAME_MAX:
        raise ToolError(
            "dns_lookup: 'hostname' muss 1..253 Zeichen sein"
        )
    if not _HOSTNAME_RE.match(h):
        raise ToolError(
            f"dns_lookup: 'hostname' enthaelt unerlaubte Zeichen: {h!r}"
        )
    check_target_allowed(h)
    try:
        infos = socket.getaddrinfo(h, None)
    except socket.gaierror as exc:
        raise ToolError(f"dns_lookup: DNS-Fehler fuer {h!r}: {exc}") from exc
    except OSError as exc:
        raise ToolError(f"dns_lookup: OSError: {exc}") from exc
    addresses = sorted({info[4][0] for info in infos})
    return {
        "hostname": h,
        "addresses": addresses,
        "source": "dns_lookup",
    }

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool

DNS_LOOKUP_TOOL = Tool(
    name="dns_lookup",
    level=Level.READ,
    func=dns_lookup_run,
    description="Loest einen Hostnamen auf (IPv4 + IPv6).",
    version="0.1.0",
    sandbox_profile="net_diag_local",
    allowed_args=frozenset({"hostname"}),
    returns="dict",
)

__all__ = [
    "DNS_LOOKUP_TOOL",
    "dns_lookup_run",
]
