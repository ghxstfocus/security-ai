"""Detection-Pipeline mit Sofort-Massnahmen-Hook.

Die Pipeline verarbeitet Findings und ruft pro Finding die
Sofort-Massnahme auf. Die Detection-Logik selbst bleibt
unveraendert; diese Klasse fuegt nur den Hook hinzu.

Fail-closed: Fehler in der Sofort-Massnahme fuehren NICHT
zum Abbruch der Pipeline. Das Finding wird trotzdem
zurueckgegeben, der Fehler wird als Audit-Eintrag mit
status=FAILED protokolliert.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.risk.models import Finding
    from core.services.immediate_action_service import (
        ImmediateActionService,
    )

logger = logging.getLogger(__name__)


class DetectionPipeline:
    """Verarbeitet Findings und wendet Sofort-Massnahmen an."""

    def __init__(
        self,
        immediate_action_service: ImmediateActionService | None = None,
    ) -> None:
        self._immediate_action_service = immediate_action_service

    def run(self, findings: list[Finding]) -> list[Finding]:
        """Iteriert ueber findings und wendet Sofort-Massnahmen an.

        Die findings-Liste wird unveraendert zurueckgegeben.
        """
        for finding in findings:
            self._apply_immediate_action(finding)
        return findings

    def _apply_immediate_action(self, finding: Finding) -> None:
        """Wendet die Sofort-Massnahme fuer ein Finding an.

        - Kein Service konfiguriert: No-Op (Rueckwaertskompatibilitaet).
        - Kategorie LOG_ONLY: kein execute-Aufruf.
        - Sonst: execute in try/except; bei Exception Audit-Eintrag
          status=FAILED, Exception wird NICHT propagiert.
        """
        service = self._immediate_action_service
        if service is None:
            return

        from core.risk.models import (
            ImmediateActionCategory,
            RiskCategory,
            risk_level_to_immediate_action,
        )

        category = getattr(finding, "category", None)
        if not isinstance(category, RiskCategory):
            # Unbekannte Kategorie: fail-closed,
            # Audit, kein Abbruch der Pipeline.
            logger.warning(
                "Ungueltige Kategorie %r, "
                "action=LOG_ONLY.", category)
            return

        try:
            action = risk_level_to_immediate_action(category)
        except ValueError:
            logger.warning(
                "Unbekannte Kategorie %r, "
                "action=LOG_ONLY.", category)
            return

        if action == ImmediateActionCategory.LOG_ONLY:
            return

        try:
            service.execute(finding, action)
        except Exception as exc:  # noqa: BLE001 - Fail-closed: Detection darf nicht stoppen
            logger.warning(
                "ImmediateActionService.execute fehlgeschlagen: %s", exc
            )
            # Service schreibt FAILED-Audit selbst.