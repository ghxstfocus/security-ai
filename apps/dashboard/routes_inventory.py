"""
Dashboard-Routen fuer das Inventar.

Kategorie 3 (Route, RBAC, Template).

- GET /inventory                  device.read
- GET /inventory/<identifier>     device.read

Fehler (Auflage 491, Variante D):
- InventoryServiceError (Format, identifier ungueltig)
  -> 404. Pfad-Parameter mit falschem Format sind 404,
  nicht 400 (kein Existenz-Oracle).
- unbekannter Identifier -> 404.
- InventoryOperationError (Konstruktor-None, Betrieb)
  -> NICHT fangen, globaler 500.
- Repo-Fehler: heute keine ServiceError-Klasse in
  core/inventory/*, nur SchemaVersionError(RuntimeError)
  beim Migrieren (nicht im Lese-Pfad).
Kein str(e) im Response. Kein Logging des Identifiers.
"""
from __future__ import annotations

from flask import Flask, abort, g, render_template

from apps.dashboard.decorators import require_permission
from core.inventory.repository import DeviceRepository
from core.inventory.whitelist import WhitelistRepository
from core.services.inventory_service import (
    InventoryService,
    InventoryServiceError,
)


def _build_service() -> InventoryService:
    return InventoryService(
        device_repo=DeviceRepository(g.conn),
        whitelist_repo=WhitelistRepository(g.conn),
        checker=g.access_checker,
    )


def register_inventory_routes(app: Flask) -> None:
    @app.route("/inventory", methods=["GET"])
    @require_permission("device.read")
    def inventory_list():
        service = _build_service()
        devices = service.list_devices(g.principal)
        return render_template(
            "inventory.html",
            page_title="Inventar",
            devices=devices,
        )

    @app.route("/inventory/<identifier>", methods=["GET"])
    @require_permission("device.read")
    def inventory_detail(identifier: str):
        service = _build_service()
        try:
            device = service.get_device(g.principal, identifier)
        except InventoryServiceError:
            abort(404)
        if device is None:
            abort(404)
        return render_template(
            "inventory_detail.html",
            page_title="Geraet",
            device=device,
        )


__all__ = ["register_inventory_routes"]
