# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validierungs-Checks fuer Ports."""

from __future__ import annotations

_PORT_MIN = 1
_PORT_MAX = 65535


def check_port(port: object) -> bool:
    """True genau dann, wenn port ein int (nicht bool) in 1..65535 ist."""
    if not isinstance(port, int) or isinstance(port, bool):
        return False
    return _PORT_MIN <= port <= _PORT_MAX


def check_port_range(port: object, min_port: object, max_port: object) -> bool:
    """True genau dann, wenn check_port(port) und min_port <= port <= max_port."""
    if not check_port(port):
        return False
    if not isinstance(min_port, int) or isinstance(min_port, bool):
        return False
    if not isinstance(max_port, int) or isinstance(max_port, bool):
        return False
    return min_port <= port <= max_port


def check_port_list(
    ports: object, min_port: object, max_port: object
) -> list[int]:
    """Gibt die Ports aus ports zurueck, fuer die check_port_range True liefert.

    Reihenfolge der Eingabeliste bleibt erhalten. Ist ports keine Liste
    oder kein Tupel, wird eine leere Liste zurueckgegeben.
    """
    if not isinstance(ports, (list, tuple)):
        return []
    return [
        port
        for port in ports
        if check_port_range(port, min_port, max_port)
    ]


__all__ = ["check_port", "check_port_list", "check_port_range"]
