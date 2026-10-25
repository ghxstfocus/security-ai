# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Change-Applier.

Wendet einen APPROVED ChangeRequest an (apply), markiert
das Ergebnis als DEPLOYED und fuehrt bei Bedarf ein Rollback
aus (rollback).

Implementiert in Commit 4e244ff (RERUN-80). Fail-closed-
Semantik: unbekannter Typ, fehlender Handler oder Audit-
Fehler fuehren zum Abbruch, kein "silent no-op".
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.changes.models import ChangeRequest

_SUPPORTED_TYPES: frozenset[str] = frozenset(
    {
        "config_change",
        "code_change",
        "policy_change",
        "firewall_change",
        "device_whitelist_change",
    }
)
_DEFAULT_BACKUP_DIR = "changes/backups"


class ApplierError(RuntimeError):
    """Fehler beim Anwenden oder Rollback eines Changes."""


class ApplierNotSupportedError(ApplierError):
    """Der change.type wird vom Applier nicht unterstuetzt."""


class ApplierStateError(ApplierError):
    """Falscher Zustand, z. B. rollback ohne DEPLOYED oder ohne Backup."""


class ApplierHandlerError(ApplierError):
    """Ein Handler hat backup/apply/restore nicht geschafft."""


@dataclass(frozen=True)
class ApplyResult:
    """Ergebnis eines apply()-Aufrufs."""

    change_id: str
    applied: bool
    idempotent_skip: bool
    backup_path: str | None


@dataclass(frozen=True)
class RollbackResult:
    """Ergebnis eines rollback()-Aufrufs."""

    change_id: str
    rolled_back: bool
    idempotent_skip: bool
    restored_from: str | None


class ChangeApplier:
    """
    Applier fuer ChangeRequests.

    Der Konstruktor nimmt optional Abhaengigkeiten
    (z. B. AuditWriter, ChangeRepository), damit spaetere
    Implementierungen nichts an der Signatur aendern muessen.

    Handler-Protokoll (Duck-Typing, keine harte Klassenhierarchie):
    Jeder Handler muss folgende Methoden bereitstellen:

    - ``backup(change) -> dict``
      Erzeugt einen serialisierbaren Snapshot des aktuellen Zustands.
    - ``apply(change, backup) -> None``
      Wendet den Change an. ``backup`` ist der zuvor erzeugte Snapshot.
    - ``restore(backup) -> None``
      Stellt den Zustand aus dem Snapshot wieder her.
    - ``restore_from_plan(change, plan) -> None`` (optional)
      Alternative Wiederherstellung anhand eines Plans; wird nur
      aufgerufen, wenn vorhanden.

    Fakes in Tests muessen nur die tatsaechlich genutzten Methoden
    implementieren; fehlende optionale Methoden werden nicht erzwungen.
    """

    def __init__(self, **deps: Any) -> None:
        self._deps = dict(deps)
        self._backup_dir = Path(deps.get("backup_dir", _DEFAULT_BACKUP_DIR))
        handlers = deps.get("handlers") or {}
        self._handlers: dict[str, Any] = dict(handlers)

    def _store_backup(self, change_id: str, backup: Any) -> str:
        """Persistiert ein Backup und liefert den Ablagepfad."""
        self._backup_dir.mkdir(parents=True, exist_ok=True)
        path = self._backup_dir / f"{change_id}.json"
        path.write_text(
            json.dumps(backup, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return str(path)

    def _load_backup_path(self, change_id: str) -> str | None:
        """Liefert den Backup-Pfad fuer change_id, falls vorhanden."""
        resolver = self._deps.get("backup_resolver")
        if resolver is not None:
            return resolver(change_id)
        path = self._backup_dir / f"{change_id}.json"
        if not path.exists():
            return None
        return str(path)

    def apply(self, change: ChangeRequest) -> ApplyResult:
        """
        Wendet einen APPROVED Change an.

        Schrittfolge:
        1. change_id pruefen (sonst ApplierError).
        2. change.type gegen _SUPPORTED_TYPES pruefen
           (sonst ApplierNotSupportedError).
        3. Idempotenz: status == "DEPLOYED" -> ApplyResult mit
           applied=False und idempotent_skip=True.
        4. Handler fuer change.type holen (sonst ApplierError).
        5. handler.backup(change) aufrufen; jeder Fehler wird als
           ApplierHandlerError weitergereicht (fail closed).
        6. Backup unter self._backup_dir ablegen.
        7. handler.apply(change) aufrufen; jeder Fehler wird als
           ApplierHandlerError weitergereicht.
        8. ApplyResult(change_id, backup) zurueckgeben.
        """
        change_id = getattr(change, "change_id", None)
        if not change_id:
            raise ApplierError("change_id fehlt")

        change_type = getattr(change, "type", None)
        if change_type not in _SUPPORTED_TYPES:
            raise ApplierNotSupportedError(
                f"change.type={change_type!r} wird nicht unterstuetzt"
            )

        status = getattr(change, "status", None)
        if status is not None and str(status).upper() == "DEPLOYED":
            return ApplyResult(
                change_id=change_id,
                applied=False,
                idempotent_skip=True,
                backup_path=None,
            )

        handler = self._handlers.get(change_type)
        if handler is None:
            raise ApplierError(f"kein Handler fuer type={change_type}")

        try:
            backup = handler.backup(change)
        except ApplierError:
            raise
        except Exception as exc:
            raise ApplierHandlerError(
                f"backup fehlgeschlagen fuer change_id={change_id}: {exc}"
            ) from exc

        backup_path = self._store_backup(change_id, backup)

        try:
            handler.apply(change)
        except ApplierError:
            raise
        except Exception as exc:
            raise ApplierHandlerError(
                f"apply fehlgeschlagen fuer change_id={change_id}: {exc}"
            ) from exc

        return ApplyResult(
            change_id=change_id,
            applied=True,
            idempotent_skip=False,
            backup_path=backup_path,
        )

    def rollback(self, change: ChangeRequest) -> RollbackResult:
        """
        Rollt einen DEPLOYED Change zurueck.

        Schrittfolge:
        1. change_id pruefen (sonst ApplierError).
        2. status pruefen: bereits ROLLED_BACK -> idempotenter Skip.
           Anderer Status als DEPLOYED -> ApplierStateError.
           Fehlt status, dient das Backup als Wahrheitsquelle.
        3. Backup-Datei unter self._backup_dir pruefen; fehlt sie
           -> ApplierStateError.
        4. Backup laden; Parse-Fehler -> ApplierStateError.
        5. change.type gegen _SUPPORTED_TYPES pruefen
           (sonst ApplierNotSupportedError).
        6. Handler fuer change.type holen (sonst ApplierError).
        7. handler.restore(change, backup) aufrufen; jeder Fehler
           wird als ApplierHandlerError weitergereicht.
        8. RollbackResult(change_id, rolled_back=True,
           idempotent_skip=False, restored_from=backup_path)
           zurueckgeben.
        """
        change_id = getattr(change, "change_id", None)
        if not change_id:
            raise ApplierError("change_id fehlt")

        status = getattr(change, "status", None)
        if status is not None and str(status).upper() == "ROLLED_BACK":
            return RollbackResult(
                change_id=change_id,
                rolled_back=False,
                idempotent_skip=True,
                restored_from=None,
            )
        if status is not None and str(status).upper() != "DEPLOYED":
            raise ApplierStateError(
                f"rollback nur fuer DEPLOYED erlaubt (status={status!r})"
            )

        backup_path = self._backup_dir / f"{change_id}.json"
        if not backup_path.exists():
            raise ApplierStateError(
                f"kein Backup fuer change_id={change_id} vorhanden"
            )

        try:
            backup = json.loads(backup_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ApplierStateError(
                f"Backup fuer change_id={change_id} nicht lesbar: {exc}"
            ) from exc

        change_type = getattr(change, "type", None)
        if change_type not in _SUPPORTED_TYPES:
            raise ApplierNotSupportedError(
                f"change.type={change_type!r} wird nicht unterstuetzt"
            )

        handler = self._handlers.get(change_type)
        if handler is None:
            raise ApplierError(f"kein Handler fuer type={change_type}")

        try:
            handler.restore(change, backup)
        except ApplierError:
            raise
        except Exception as exc:
            raise ApplierHandlerError(
                f"restore fehlgeschlagen fuer change_id={change_id}: {exc}"
            ) from exc

        return RollbackResult(
            change_id=change_id,
            rolled_back=True,
            idempotent_skip=False,
            restored_from=str(backup_path),
        )


__all__ = [
    "ApplierError",
    "ApplierHandlerError",
    "ApplierNotSupportedError",
    "ApplierStateError",
    "ApplyResult",
    "ChangeApplier",
    "RollbackResult",
]
