"""Echte Implementierung des ChangeAppliers.

Liest die Ziel-YAML, erstellt ein Backup und merged
den payload rekursiv in die geladene Struktur.

Merge-Semantik:
  - dict-Werte werden rekursiv gemerged.
  - Listen werden ERSETZT (nicht anghaengt).
  - Skalare ueberschreiben.

Fail-closed (U2a3):
  - Jeder Fehler in apply() setzt change.state = FAILED
    und propagiert (kein silent no-op).
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from .models import Change, ChangeState

if TYPE_CHECKING:
    from harness.audit.writer import AuditWriter


def _merge(base: Any, overlay: Any) -> Any:
    """Merged overlay rekursiv in base.

    - dict + dict: rekursiv.
    - alles andere: overlay ersetzt base.
    """
    if isinstance(base, dict) and isinstance(overlay, dict):
        result: dict = dict(base)
        for key, value in overlay.items():
            if key in result:
                result[key] = _merge(result[key], value)
            else:
                result[key] = value
        return result
    return overlay


class ChangeApplier:
    """Wendet Changes auf eine Konfigurationsdatei an."""

    def __init__(
        self,
        config_path: Path,
        backup_dir: Path,
        audit_writer: AuditWriter | None = None,
    ) -> None:
        self.config_path = config_path
        self.backup_dir = backup_dir
        self._audit_writer = audit_writer

    def apply(self, change: Change) -> None:
        """Wendet einen Change an.

        Validiert target gegen config_path, erstellt ein
        Backup und schreibt die gemergte YAML zurueck.

        Fail-closed: Jeder Fehler (Target-Validierung,
        YAML-Parse, IO, Payload-Typ) setzt
        change.state = FAILED und propagiert.
        """
        try:
            if change.target != str(self.config_path):
                raise ValueError(
                    f"Change.target {change.target!r} passt nicht zu "
                    f"config_path {str(self.config_path)!r}"
                )

            self._backup(change)

            with self.config_path.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}

            merged = _merge(data, change.payload)

            with self.config_path.open("w", encoding="utf-8") as handle:
                yaml.safe_dump(merged, handle, sort_keys=False)

            if self._audit_writer is not None:
                self._audit_writer.log(
                    agent="security_ai",
                    tool="changeapplier",
                    policy_result="ALLOWED",
                    permission_level=0,
                    execution_status="OK",
                    details={
                        "change_id": change.id,
                        "status": ChangeState.APPLIED.value,
                    },
                )
        except yaml.YAMLError as exc:
            # U2a3: yaml.YAMLError ist keine ValueError-
            # Subklasse. Aufrufer (und Test) erwarten
            # aber ValueError als einheitliche Exception
            # fuer ungueltige Eingaben. Deshalb wrappen.
            change.state = ChangeState.FAILED
            raise ValueError(
                f"YAML-Parse-Fehler in {self.config_path}: "
                f"{exc}") from exc
        except Exception:
            change.state = ChangeState.FAILED
            raise

    def _backup(self, change: Change) -> Path:
        """Kopiert config_path nach backup_dir/<change.id>.bak."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = self.backup_dir / f"{change.id}.bak"
        shutil.copy2(self.config_path, backup_path)
        return backup_path

    def rollback(self, change: Change) -> None:
        """Stellt den Zustand aus dem Backup wieder her.

        Idempotent: Existiert kein Backup, ist rollback ein
        No-Op (kein Fehler). rollback ruft NICHT _backup()
        auf, damit das Original-Backup nicht ueberschrieben
        wird.
        """
        backup_path = self.backup_dir / f"{change.id}.bak"
        if not backup_path.exists():
            return
        shutil.copy2(backup_path, self.config_path)
