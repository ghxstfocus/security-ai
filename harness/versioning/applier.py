"""
Change-Applier (Stub).

Aufgabe (spaeter): einen APPROVED ChangeRequest anwenden,
Ergebnis als DEPLOYED markieren, bei Bedarf Rollback ausfuehren.

Aktueller Stand: STUB. apply() und rollback() werfen
NotImplementedError. Damit ist der Aufrufpfad klar, die
Implementierung folgt in einer spaeteren Phase.

Bewusste Entscheidung:
- Kein "silent no-op". Fail closed: wer anwendet, muss es
  wissen. Sonst koennte ein APPROVED Change als DEPLOYED
  markiert werden, ohne tatsaechlich angewendet worden zu sein.
"""
from __future__ import annotations

from typing import Any

from core.changes.models import ChangeRequest, ChangeType


class ApplierError(RuntimeError):
    """Fehler beim Anwenden oder Rollback eines Changes."""


class ChangeApplier:
    """
    Stub-Applier.

    Der Konstruktor nimmt optional Abhaengigkeiten
    (z. B. AuditWriter, ChangeRepository), damit spaetere
    Implementierungen nichts an der Signatur aendern muessen.
    """

    def __init__(self, **deps: Any) -> None:
        self._deps = dict(deps)

    def apply(self, change: ChangeRequest) -> dict[str, Any]:
        """
        Wendet einen APPROVED Change an.
        STUB: wirft NotImplementedError.
        """
        raise NotImplementedError(
            "ChangeApplier.apply ist ein Stub (Phase 4.4c). "
            "Echte Anwendung folgt in einer spaeteren Phase."
        )

    def rollback(self, change: ChangeRequest) -> dict[str, Any]:
        """
        Rollt einen DEPLOYED Change zurueck.
        STUB: wirft NotImplementedError.
        """
        raise NotImplementedError(
            "ChangeApplier.rollback ist ein Stub (Phase 4.4c). "
            "Echtes Rollback folgt in einer spaeteren Phase."
        )


__all__ = [
    "ApplierError",
    "ChangeApplier",
]
