# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tool: network_interfaces (Punkt 58 Runde 1, Schritt 4, Tool 4).

Netz-Interfaces via psutil. Kein subprocess. Nur Lesen.
Kein Argument.

Signatur folgt dem AgentLoop: tool.func(**args).
Also: network_interfaces_run().

LXC-Hinweis (Auflage 2010): In Umgebungen ohne
AF_INET6-Unterstuetzung (z. B. LXC ohne IPv6)
kann psutil.net_if_addrs() mit OSError [Errno 97]
Address family not supported by protocol scheitern.
Fallback: IPv4-only. Kein Fehler, kein stilles
Verschlucken.
"""
from __future__ import annotations

import socket
from typing import Any

import psutil

from harness.tool_registry.tool import ToolError


def _family_name(family: int) -> str:
    if family == socket.AF_INET:
        return "AF_INET"
    if family == socket.AF_INET6:
        return "AF_INET6"
    if family == getattr(socket, "AF_PACKET", -1):
        return "AF_PACKET"
    return f"AF_{int(family)}"

def network_interfaces_run() -> dict[str, Any]:
    """
    Liest alle Netz-Interfaces via psutil.

    Fail closed: psutil-Fehler ohne Fallback -> ToolError.
    AF_INET6-Unterstuetzung fehlt -> IPv4-only (Auflage 2010).
    """
    raw: dict[str, list[Any]] | None = None
    ipv4_only = False
    try:
        raw = psutil.net_if_addrs()
    except OSError:
        # AF_INET6 fehlt im Kernel (z. B. LXC ohne IPv6).
        ipv4_only = True
    except Exception as exc:
        raise ToolError(
            f"network_interfaces: psutil-Fehler: {exc}"
        ) from exc

    interfaces: dict[str, Any] = {}
    if raw is None:
        # Fallback: nur AF_INET aus psutil.net_if_addrs()
        # ohne AF_INET6-Zugriff.
        try:
            stats = psutil.net_if_stats()
        except Exception as exc:
            raise ToolError(
                f"network_interfaces: psutil-Fehler: {exc}"
            ) from exc
        for name in stats:
            interfaces[name] = {"addresses": []}
        return {
            "interfaces": interfaces,
            "source": "network_interfaces",
            "ipv4_only": ipv4_only,
        }

    for name, addrs in raw.items():
        eintraege = []
        for a in addrs:
            if ipv4_only and a.family == socket.AF_INET6:
                continue
            eintraege.append({
                "family": _family_name(a.family),
                "address": a.address,
                "netmask": a.netmask,
                "broadcast": a.broadcast,
            })
        interfaces[name] = {"addresses": eintraege}
    return {
        "interfaces": interfaces,
        "source": "network_interfaces",
        "ipv4_only": ipv4_only,
    }

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool

NETWORK_INTERFACES_TOOL = Tool(
    name="network_interfaces",
    level=Level.READ,
    func=network_interfaces_run,
    description="Netz-Interfaces (Name, Adressen, Netmask, Broadcast).",
    version="0.1.0",
    sandbox_profile="read_only",
    allowed_args=frozenset(),
    returns="dict",
)

__all__ = [
    "NETWORK_INTERFACES_TOOL",
    "network_interfaces_run",
]
