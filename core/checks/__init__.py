# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validierungs-Checks fuer Ports.

Dieses Modul stellt Funktionen zur Verfuegung, um Ports und Portlisten
zu validieren. Es werden sowohl einzelne Ports als auch Listen von Ports
geprueft, gefiltert, gezaehlt und summiert. Zusaetzlich gibt es eine
spezielle Pruefung fuer Ping-Ports.

Oeffentliche API:
    check_port(port) -> bool
        Prueft, ob ein einzelner Port gueltig ist (int, nicht bool, 1..65535).
    check_port_range(port, min_port, max_port) -> bool
        Prueft, ob ein Port gueltig und im angegebenen Bereich liegt.
    check_port_list(ports, min_port, max_port) -> list[int]
        Filtert eine Liste von Ports nach gueltigen Ports im Bereich.
    check_port_count(ports, min_port, max_port) -> int
        Zaehlt die gueltigen Ports in einer Liste.
    check_port_sum(ports, min_port, max_port) -> int
        Summiert die gueltigen Ports in einer Liste.
    check_port_ping(port, min_port, max_port) -> bool
        Prueft, ob ein Port ein gueltiger Ping-Port (80, 443, 8080) ist.

Grenzfall-Tests:
    Fuer jede Funktion existieren Tests, die Grenzfaelle abdecken,
    z. B. ungueltige Typen (None, str, bool), leere Listen, Ports
    ausserhalb des Bereichs und Randwerte (1, 65535).
    Siehe tests/test_checks.py.
"""

from __future__ import annotations

_PORT_MIN = 1
_PORT_MAX = 65535


def check_port(port: object) -> bool:
    """Prueft, ob port ein gueltiger Port ist.

    Args:
        port: Zu pruefender Wert.

    Returns:
        True, wenn port ein int (nicht bool) im Bereich 1..65535 ist,
        sonst False.

    Raises:
        Keine.
    """
    if not isinstance(port, int) or isinstance(port, bool):
        return False
    return _PORT_MIN <= port <= _PORT_MAX


def check_port_range(port: object, min_port: object, max_port: object) -> bool:
    """Prueft, ob port ein gueltiger Port im angegebenen Bereich ist.

    Args:
        port: Zu pruefender Port.
        min_port: Untere Grenze (inklusive).
        max_port: Obere Grenze (inklusive).

    Returns:
        True, wenn check_port(port) True ist und min_port <= port <= max_port
        gilt, sonst False.

    Raises:
        Keine.
    """
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
    """Filtert eine Portliste nach gueltigen Ports im Bereich.

    Args:
        ports: Liste oder Tupel von Ports.
        min_port: Untere Grenze (inklusive).
        max_port: Obere Grenze (inklusive).

    Returns:
        Liste der Ports aus ports, fuer die check_port_range True liefert.
        Die Reihenfolge der Eingabe bleibt erhalten. Ist ports keine Liste
        oder kein Tupel, wird eine leere Liste zurueckgegeben.

    Raises:
        Keine.
    """
    if not isinstance(ports, (list, tuple)):
        return []
    return [
        port
        for port in ports
        if check_port_range(port, min_port, max_port)
    ]


def check_port_count(
    ports: object, min_port: object, max_port: object
) -> int:
    """Zaehlt die gueltigen Ports in einer Portliste.

    Args:
        ports: Liste oder Tupel von Ports.
        min_port: Untere Grenze (inklusive).
        max_port: Obere Grenze (inklusive).

    Returns:
        Anzahl der Ports aus ports, fuer die check_port_range True liefert.
        Ist ports keine Liste oder kein Tupel, wird 0 zurueckgegeben.

    Raises:
        Keine.
    """
    if not isinstance(ports, (list, tuple)):
        return 0
    return sum(
        1
        for port in ports
        if check_port_range(port, min_port, max_port)
    )


def check_port_sum(
    ports: object, min_port: object, max_port: object
) -> int:
    """Summiert die gueltigen Ports in einer Portliste.

    Args:
        ports: Liste oder Tupel von Ports.
        min_port: Untere Grenze (inklusive).
        max_port: Obere Grenze (inklusive).

    Returns:
        Summe der Ports aus ports, fuer die check_port_range True liefert.
        Ist ports keine Liste oder kein Tupel, wird 0 zurueckgegeben.

    Raises:
        Keine.
    """
    if not isinstance(ports, (list, tuple)):
        return 0
    return sum(
        port
        for port in ports
        if check_port_range(port, min_port, max_port)
    )


def check_port_ping(
    port: object, min_port: object, max_port: object
) -> bool:
    """Prueft, ob port ein gueltiger Ping-Port im Bereich ist.

    Args:
        port: Zu pruefender Port.
        min_port: Untere Grenze (inklusive).
        max_port: Obere Grenze (inklusive).

    Returns:
        True, wenn check_port_range True liefert und port in (80, 443, 8080)
        liegt, sonst False.

    Raises:
        Keine.
    """
    if not check_port_range(port, min_port, max_port):
        return False
    return port in (80, 443, 8080)


__all__ = [
    "check_port",
    "check_port_count",
    "check_port_list",
    "check_port_ping",
    "check_port_range",
    "check_port_sum",
]
