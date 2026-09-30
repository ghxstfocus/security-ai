"""
FritzboxStateService: liest den Watcher-Zustand.

Kategorie 3 (Kern-Service, RBAC, Datei-IO).

Der Fritz!Box-Watcher (tools/fritzbox_watcher.py) schreibt
alle 60s data/fritzbox_state.json. Dieser Service liest
die Datei fuer das Dashboard (T1: Live-Geraete).

Regeln:
- RBAC: device.read.
- Fail open bei fehlender/kaputter Datei:
  {"available": False, "hosts": {}}.
  Kein 500, keine Falsch-Aussage.
- Fail closed bei RBAC (AccessDeniedError).
- Kein Cache: jeder Aufruf liest frisch.
"""
from __future__ import annotations

import json
from pathlib import Path

from core.access.checker import AccessChecker
from core.services import OperationError, ServiceError

DEFAULT_STATE_PATH = Path("data/fritzbox_state.json")


class FritzboxStateServiceError(ServiceError):
    """Fachlicher Fehler im FritzboxStateService (4xx)."""


class FritzboxStateOperationError(OperationError):
    """Betriebsfehler im FritzboxStateService (5xx)."""


class FritzboxStateService:
    def __init__(
        self,
        checker: AccessChecker,
        state_path: Path | str | None = None,
    ) -> None:
        if checker is None:
            raise FritzboxStateOperationError(
                "checker ist Pflicht (fail closed)"
            )
        self._checker = checker
        self._path = Path(
            state_path if state_path is not None
            else DEFAULT_STATE_PATH
        )

    def _require(self, actor: str, code: str) -> None:
        self._checker.require_permission(actor, code)

    def get_state(self, actor: str) -> dict:
        """Liest data/fritzbox_state.json.

        Rueckgabe:
            {"available": True, "hosts": {...}}
            oder
            {"available": False, "hosts": {}}

        RBAC: device.read.
        """
        self._require(actor, "device.read")
        try:
            raw = self._path.read_text(encoding="utf-8")
        except (OSError, FileNotFoundError):
            return {"available": False, "hosts": {}}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {"available": False, "hosts": {}}
        hosts = data.get("hosts") if isinstance(data, dict) else None
        if not isinstance(hosts, dict):
            return {"available": False, "hosts": {}}
        return {"available": True, "hosts": hosts}


__all__ = [
    "DEFAULT_STATE_PATH",
    "FritzboxStateOperationError",
    "FritzboxStateService",
    "FritzboxStateServiceError",
]
