# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Dashboard-Startseite mit Live-Kacheln.

Kategorie 3 (Route, RBAC, Template).

Auflage 290: stat_card als Makro.
Auflage 1275-1298: vier Kacheln mit Live-Werten.

Kachel-Werte:
- Geraete: InventoryService.list_devices (device.read).
- Alarme (24h): AuditReaderService.list_recent_assessments
  (alert.view).
- Offene Approvals: ApprovalService.list_pending
  (approval.view).
- Changes: ChangeService.list_all (change.view).

Fehlerverhalten pro Kachel (A1284, L2):
- AccessDeniedError -> Wert "—", kein Log.
- Anderer Fehler -> Wert "—", Log ERROR ohne Details.
- Kein abort(500). Andere Kacheln bleiben sichtbar.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from flask import Flask, g, render_template

from apps.dashboard.decorators import require_permission
from core.access.checker import AccessDeniedError
from core.changes.repository import ChangeRepository
from core.inventory.repository import DeviceRepository
from core.inventory.whitelist import WhitelistRepository
from core.services.approval_service import ApprovalService
from core.services.audit_reader_service import AuditReaderService
from core.services.change_service import ChangeService
from core.services.inventory_service import InventoryService
from harness.approval.queue import ApprovalQueue

log = logging.getLogger(__name__)

_FALLBACK = "—"


def _safe_count(fn: Callable[[], Any]) -> int | str:
    """Kachel-Wert oder "—" (A1284, L2)."""
    try:
        return len(fn())
    except AccessDeniedError:
        return _FALLBACK
    except Exception:  # noqa: BLE001 - Anzeige fail open
        log.error("Kachel: Service-Fehler")
        return _FALLBACK


def _count_devices() -> int | str:
    return _safe_count(lambda: InventoryService(
        device_repo=DeviceRepository(g.conn),
        whitelist_repo=WhitelistRepository(g.conn),
        checker=g.access_checker,
    ).list_devices(g.principal))


def _count_alerts() -> int | str:
    return _safe_count(lambda: AuditReaderService(
        audit_writer=g.audit,
        checker=g.access_checker,
    ).list_recent_assessments(g.principal))


def _count_approvals() -> int | str:
    return _safe_count(lambda: ApprovalService(
        queue=ApprovalQueue(g.conn, g.audit),
        checker=g.access_checker,
    ).list_pending(g.principal))


def _count_network(net: str) -> int | str:
    """Kachel-Wert "Anzahl Geraete im Netz net".

    Nicht ueber _safe_count, weil count_by_network
    direkt eine Zahl liefert (nicht eine Liste).
    _safe_count wuerde len(int) aufrufen -> TypeError.
    """
    try:
        return InventoryService(
            device_repo=DeviceRepository(g.conn),
            whitelist_repo=WhitelistRepository(g.conn),
            checker=g.access_checker,
        ).count_by_network(g.principal).get(net, 0)
    except AccessDeniedError:
        return _FALLBACK
    except Exception:  # noqa: BLE001 - Anzeige fail open
        log.error("Kachel: Service-Fehler")
        return _FALLBACK


def _count_changes() -> int | str:
    return _safe_count(lambda: ChangeService(
        repo=ChangeRepository(g.conn),
        checker=g.access_checker,
        audit_writer=g.audit,
    ).list_all(g.principal))


def register_index_routes(app: Flask) -> None:
    @app.route("/", methods=["GET"])
    @require_permission("device.read")
    def index() -> str:
        return render_template(
            "index.html",
            page_title="Dashboard",
            device_count=_count_devices(),
            network_hauptnetz=_count_network("Hauptnetz"),
            network_gastnetz=_count_network("Gastnetz"),
            network_extern=_count_network("Extern"),
            alert_count=_count_alerts(),
            approval_count=_count_approvals(),
            change_count=_count_changes(),
        )


__all__ = ["register_index_routes"]
