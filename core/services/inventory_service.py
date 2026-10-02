# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
InventoryService: Service-Schicht fuer Inventar.

Kapselt DeviceRepository + WhitelistRepository. Der Web-Layer
(apps/dashboard/routes_inventory.py) darf NICHT direkt auf die
Repositories zugreifen (DESIGN_DECISIONS §11).

Design:
- Lesen: RBAC device.read, kein Audit.
- Schreiben (Whitelist-Pflege, Punkt 56a):
  RBAC whitelist.manage, Audit-Pflicht.
  audit_writer ist im Konstruktor optional, aber bei
  schreibenden Methoden Pflicht (fail closed).
- Schreiben (Internal-Name, Punkt 75):
  RBAC device.write, Audit-Pflicht.
  internal_name ist Nutzer-Eigentum, nicht Watcher-Feld.
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
from core.services import OperationError, ServiceError
from harness.audit.writer import AuditWriter

IDENTIFIER_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,253}[A-Za-z0-9])?$"
)
HISTORY_LIMIT = 100
INTERNAL_NAME_MAX = 80


class InventoryServiceError(ServiceError):
    """Fachlicher Fehler im InventoryService (4xx)."""


class InventoryOperationError(OperationError):
    """Betriebsfehler im InventoryService (5xx)."""


class InventoryService:
    def __init__(
        self,
        device_repo: DeviceRepository,
        whitelist_repo: WhitelistRepository,
        checker: AccessChecker,
        audit_writer: AuditWriter | None = None,
    ) -> None:
        if device_repo is None:
            raise InventoryOperationError(
                "device_repo ist Pflicht (fail closed)"
            )
        if whitelist_repo is None:
            raise InventoryOperationError(
                "whitelist_repo ist Pflicht (fail closed)"
            )
        if checker is None:
            raise InventoryOperationError(
                "checker ist Pflicht (fail closed)"
            )
        self._devices = device_repo
        self._whitelist = whitelist_repo
        self._checker = checker
        self._audit = audit_writer

    def _log(self, kind: str, **extra: object) -> None:
        """Audit-Eintrag. Fail closed, wenn kein AuditWriter gesetzt."""
        if self._audit is None:
            raise InventoryOperationError(
                "audit_writer fehlt (fail closed)"
            )
        details: dict = {"kind": kind}
        details.update(extra)
        self._audit.log(
            agent="security_ai",
            tool="inventory_service",
            policy_result="ALLOWED",
            permission_level=0,
            execution_status="OK",
            details=details,
        )

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

    def count_by_network(self, actor: str) -> dict[str, int]:
        """Geraete-Anzahl pro network_type (T3, Auflage 1688).

        RBAC: device.read.
        Rueckgabe: alle drei bekannten Keys, 0 bei fehlend.
        """
        self._require(actor, "device.read")
        return self._devices.count_by_network()

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

    def add_to_whitelist(
        self,
        actor: str,
        identifier: str,
        *,
        notes: str | None = None,
    ) -> dict:
        """Whitelist-Eintrag anlegen (Punkt 56a).

        RBAC: whitelist.manage.
        Audit: whitelist_added.
        Idempotent: vorhandener Eintrag wird unveraendert
        zurueckgegeben, aber trotzdem auditiert.
        """
        self._require(actor, "whitelist.manage")
        ident = self._validate_identifier(identifier)
        device = self._devices.get(ident)
        # Fallback-Kette (Punkt 75): internal_name or
        # entity_name or identifier.
        if device is not None:
            entity_name = (
                device.internal_name
                or device.entity_name
                or ident
            )
        else:
            entity_name = ident
        try:
            entry = self._whitelist.add(
                ident,
                entity_name,
                added_by=actor,
                notes=notes,
            )
        except Exception as exc:
            raise InventoryOperationError(
                f"Whitelist-Add fehlgeschlagen: {exc}"
            ) from exc
        self._log(
            "whitelist_added",
            identifier=ident,
            entity_name=entity_name,
            added_by=actor,
        )
        return entry.to_dict()

    def remove_from_whitelist(self, actor: str, identifier: str) -> dict:
        """Whitelist-Eintrag entfernen (Punkt 56a).

        RBAC: whitelist.manage.
        Audit: whitelist_removed.
        Rueckgabe: dict mit removed=True/False.
        """
        self._require(actor, "whitelist.manage")
        ident = self._validate_identifier(identifier)
        try:
            removed = self._whitelist.remove(ident, removed_by=actor)
        except Exception as exc:
            raise InventoryOperationError(
                f"Whitelist-Remove fehlgeschlagen: {exc}"
            ) from exc
        self._log(
            "whitelist_removed",
            identifier=ident,
            removed_by=actor,
            removed=bool(removed),
        )
        return {"identifier": ident, "removed": bool(removed)}

    def set_internal_name(
        self,
        actor: str,
        identifier: str,
        name: str | None,
    ) -> dict:
        """Setzt oder loescht den internen Namen (Punkt 75).

        RBAC: device.write.
        Audit: internal_name_set.
        Validierung: max 80 Zeichen, strip.
        Leerer String oder None -> None (loeschen).
        """
        self._require(actor, "device.write")
        ident = self._validate_identifier(identifier)

        if name is None:
            clean: str | None = None
        elif not isinstance(name, str):
            raise InventoryServiceError("name muss String sein")
        else:
            stripped = name.strip()
            if not stripped:
                clean = None
            else:
                if len(stripped) > INTERNAL_NAME_MAX:
                    raise InventoryServiceError(
                        f"name zu lang (max {INTERNAL_NAME_MAX})"
                    )
                clean = stripped

        device = self._devices.get(ident)
        if device is None:
            raise InventoryServiceError("Geraet unbekannt")

        try:
            self._devices.set_internal_name(ident, clean)
        except Exception as exc:
            raise InventoryOperationError(
                f"internal_name setzen fehlgeschlagen: {exc}"
            ) from exc

        self._log(
            "internal_name_set",
            identifier=ident,
            internal_name=clean,
            actor=actor,
        )
        result = self._devices.get(ident)
        return result.to_dict() if result is not None else {
            "identifier": ident,
            "internal_name": clean,
        }


__all__ = [
    "HISTORY_LIMIT",
    "IDENTIFIER_RE",
    "INTERNAL_NAME_MAX",
    "InventoryOperationError",
    "InventoryService",
    "InventoryServiceError",
]
