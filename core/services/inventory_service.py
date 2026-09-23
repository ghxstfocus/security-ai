"""
InventoryService: Service-Schicht fuer Inventar-Lesen.

Kapselt DeviceRepository + WhitelistRepository. Der Web-Layer
(apps/dashboard/routes_inventory.py) darf NICHT direkt auf die
Repositories zugreifen (DESIGN_DECISIONS §11).

Design:
- Rein lesend. Kein Schreiben. Kein Audit (siehe
  DESIGN_DECISIONS §11, Audit-Pflicht nur bei Schreiben).
  Falls spaeter Lese-Audit gewuenscht: hier ergaenzen.
- RBAC: device.read vor jedem Zugriff.
- Input-Validierung (Regex + ".."-Block), sonst
  InventoryServiceError. Fail closed.
- history(identifier, limit=100) wird erst NACH der Validierung
  aufgerufen. Repository-Schicht ist nicht die Validierungsgrenze.
"""
from __future__ import annotations

import re

from core.access.checker import AccessChecker
from core.inventory.repository import DeviceRepository
from core.inventory.whitelist import WhitelistRepository
from core.services import ServiceError


IDENTIFIER_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,253}[A-Za-z0-9])?$"
)
HISTORY_LIMIT = 100


class InventoryServiceError(ServiceError):
    """Fachlicher Fehler im InventoryService."""


class InventoryService:
    def __init__(
        self,
        device_repo: DeviceRepository,
        whitelist_repo: WhitelistRepository,
        checker: AccessChecker,
    ) -> None:
        if device_repo is None:
            raise InventoryServiceError(
                "device_repo ist Pflicht (fail closed)"
            )
        if whitelist_repo is None:
            raise InventoryServiceError(
                "whitelist_repo ist Pflicht (fail closed)"
            )
        if checker is None:
            raise InventoryServiceError(
                "checker ist Pflicht (fail closed)"
            )
        self._devices = device_repo
        self._whitelist = whitelist_repo
        self._checker = checker

    def _require(self, actor: str, code: str) -> None:
        self._checker.require_permission(actor, code)

    def _validate_identifier(self, identifier: object) -> str:
        if not isinstance(identifier, str):
            raise InventoryServiceError("identifier muss String sein")
        if not IDENTIFIER_RE.match(identifier):
            raise InventoryServiceError("identifier ungueltig")
        if ".." in identifier:
            raise InventoryServiceError("identifier ungueltig")
        return identifier

    def list_devices(self, actor: str) -> list[dict]:
        """Alle Geraete. RBAC: device.read. Reihenfolge: last_seen DESC."""
        self._require(actor, "device.read")
        out: list[dict] = []
        for d in self._devices.list_all():
            entry = d.to_dict()
            entry["whitelisted"] = self._whitelist.is_whitelisted(
                d.identifier
            )
            out.append(entry)
        return out

    def get_device(self, actor: str, identifier: str) -> dict | None:
        """
        Ein Geraet samt History. RBAC: device.read.

        Rueckgabe: None, wenn unbekannt (Route -> 404).
        InventoryServiceError bei ungueltigem Identifier
        (Route -> 404, kein str(e) im Response).
        """
        self._require(actor, "device.read")
        ident = self._validate_identifier(identifier)
        device = self._devices.get(ident)
        if device is None:
            return None
        entry = device.to_dict()
        entry["whitelisted"] = self._whitelist.is_whitelisted(ident)
        entry["history"] = self._devices.history(
            ident, limit=HISTORY_LIMIT,
        )
        return entry


__all__ = [
    "HISTORY_LIMIT",
    "IDENTIFIER_RE",
    "InventoryService",
    "InventoryServiceError",
]
