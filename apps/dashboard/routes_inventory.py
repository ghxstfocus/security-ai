"""
Dashboard-Routen fuer das Inventar.

Kategorie 3 (Route, RBAC, Template).

- GET  /inventory                            device.read
- GET  /inventory/<identifier>               device.read
- POST /inventory/<identifier>/whitelist/add
                                              whitelist.manage
- GET  /inventory/<identifier>/whitelist/remove
                                              whitelist.manage (Bestaetigung)
- POST /inventory/<identifier>/whitelist/remove
                                              whitelist.manage (Ausfuehrung)
- POST /inventory/<identifier>/internal_name
                                              device.write

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

from flask import (
    Flask,
    Response,
    abort,
    g,
    render_template,
    request,
    session,
    url_for,
)

from apps.dashboard import csrf
from apps.dashboard._redirect import safe_redirect
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
        audit_writer=getattr(g, "audit", None),
    )


def register_inventory_routes(app: Flask) -> None:
    @app.route("/inventory", methods=["GET"])
    @require_permission("device.read")
    def inventory_list() -> str:
        service = _build_service()
        devices = service.list_devices(g.principal)
        return render_template(
            "inventory.html",
            page_title="Inventar",
            devices=devices,
        )

    @app.route("/inventory/<identifier>", methods=["GET"])
    @require_permission("device.read")
    def inventory_detail(identifier: str) -> str:
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

    @app.route(
        "/inventory/<identifier>/whitelist/add",
        methods=["POST"],
    )
    @require_permission("whitelist.manage")
    def inventory_whitelist_add(identifier: str) -> Response | tuple[str, int]:
        submitted = request.form.get("_csrf_token")
        expected = session.get("_csrf_token")
        if not csrf.validate(submitted, expected):
            return ("Ungueltige Anfrage", 400)
        service = _build_service()
        try:
            service.add_to_whitelist(g.principal, identifier)
        except InventoryServiceError:
            abort(404)
        return safe_redirect(url_for(
            "inventory_detail", identifier=identifier,
        ))

    @app.route(
        "/inventory/<identifier>/whitelist/remove",
        methods=["GET"],
    )
    @require_permission("whitelist.manage")
    def inventory_whitelist_remove_confirm(identifier: str) -> str:
        service = _build_service()
        try:
            device = service.get_device(g.principal, identifier)
        except InventoryServiceError:
            abort(404)
        if device is None:
            abort(404)
        return render_template(
            "inventory_whitelist_remove.html",
            page_title="Whitelist entfernen",
            device=device,
        )

    @app.route(
        "/inventory/<identifier>/whitelist/remove",
        methods=["POST"],
    )
    @require_permission("whitelist.manage")
    def inventory_whitelist_remove(identifier: str) -> Response | tuple[str, int]:
        submitted = request.form.get("_csrf_token")
        expected = session.get("_csrf_token")
        if not csrf.validate(submitted, expected):
            return ("Ungueltige Anfrage", 400)
        service = _build_service()
        try:
            service.remove_from_whitelist(g.principal, identifier)
        except InventoryServiceError:
            abort(404)
        return safe_redirect(url_for(
            "inventory_detail", identifier=identifier,
        ))

    @app.route(
        "/inventory/<identifier>/internal_name",
        methods=["POST"],
    )
    @require_permission("device.write")
    def inventory_internal_name(identifier: str) -> Response | tuple[str, int]:
        submitted = request.form.get("_csrf_token")
        expected = session.get("_csrf_token")
        if not csrf.validate(submitted, expected):
            return ("Ungueltige Anfrage", 400)
        name = request.form.get("internal_name")
        service = _build_service()
        try:
            service.set_internal_name(g.principal, identifier, name)
        except InventoryServiceError:
            abort(404)
        return safe_redirect(url_for(
            "inventory_detail", identifier=identifier,
        ))


__all__ = ["register_inventory_routes"]
