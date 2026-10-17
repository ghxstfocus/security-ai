"""Echte Implementierung des ChangeAppliers.

Liest die Ziel-YAML, erstellt ein Backup und merged
den payload rekursiv in die geladene Struktur.

Merge-Semantik:
  - dict-Werte werden rekursiv gemerged.
  - Listen werden ERSETZT (nicht anghaengt).
  - Skalare ueberschreiben.

Grenzen dieser Runde:
  - KEIN Fail-closed (U2a3).
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import yaml

from .models import Change, ChangeState


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

    def __init__(self, config_path: Path, backup_dir: Path) -> None:
        self.config_path = config_path
        self.backup_dir = backup_dir

    def apply(self, change: Change) -> None:
        """Wendet einen Change an.

        Validiert target gegen config_path, erstellt ein
        Backup und schreibt die gemergte YAML zurueck.
        """
        if change.target != str(self.config_path):
            change.state = ChangeState.FAILED
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
