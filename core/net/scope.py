# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

# Netzwerk-Ziel-Whitelist (Sandbox-Ebene).
#
# Aus tools/nmap_scan.py extrahiert (Punkt 58, Schritt 1a).
# Prueft, ob ein Ziel vollstaendig in den erlaubten Netzen liegt.
# Fail closed: jeder Verstoss -> ToolError.
from __future__ import annotations

import ipaddress
import socket

from harness.tool_registry.tool import ToolError

# Ziel-Whitelist (Defense in Depth, identisch zur Policy).
_ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    )
)
_ALLOWED_HOSTNAMES = frozenset({"localhost"})

def resolve_target_networks(
    target: str,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Ziel in Netze aufloesen (IP, CIDR, Hostname).

    Fail closed: Aufloesefehler -> ToolError.
    """
    if target in _ALLOWED_HOSTNAMES:
        return [ipaddress.ip_network("127.0.0.1/32")]

    try:
        return [ipaddress.ip_network(target, strict=False)]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ToolError(
            f"scope: Ziel {target!r} nicht aufloesbar: {exc}"
        ) from exc

    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        prefix = 32 if ip.version == 4 else 128
        nets.append(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    if not nets:
        raise ToolError(f"scope: keine IP fuer Ziel {target!r}")
    return nets

def check_target_allowed(target: str) -> None:
    """Jedes aufgeloeste Netz muss ECHTE TEILMENGE mindestens eines
    erlaubten Netzes sein (subnet_of), nicht nur ueberlappen.
    Fail closed.
    """
    for net in resolve_target_networks(target):
        allowed_same_version = [
            a for a in _ALLOWED_NETWORKS if a.version == net.version
        ]
        if not any(net.subnet_of(a) for a in allowed_same_version):  # type: ignore[arg-type]  # mypy sieht net.version-Filter nicht
            raise ToolError(
                f"scope: Ziel {target!r} ({net}) liegt nicht komplett "
                f"in den erlaubten Netzen (localhost, RFC1918)"
            )

def is_in_scope(target: str) -> bool:
    """True, wenn Ziel erlaubt. False bei Verstoss oder Fehler."""
    try:
        check_target_allowed(target)
        return True
    except ToolError:
        return False

__all__ = ["check_target_allowed", "is_in_scope", "resolve_target_networks"]
