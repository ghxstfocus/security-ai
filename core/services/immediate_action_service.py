"""Sofort-Massnahmen-Ausfuehrung mit Audit.

Der Service fuehrt eine ImmediateActionCategory fuer ein
Finding aus. Jede Aktion schreibt einen Audit-Eintrag.

Grenzen:
- BLOCK/ISOLATE sind Stubs (echte Firewall-Integration
  ist eine eigene Phase). Es wird nur Audit + Notify
  ausgefuehrt.
- Idempotenz: In-Memory-Set der bereits ausgefuehrten
  finding_ids. Persistenz ist eine eigene Phase.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol

from core.risk.models import ImmediateActionCategory

if TYPE_CHECKING:
    from core.risk.models import Finding
    from harness.audit.writer import AuditWriter

logger = logging.getLogger(__name__)


class Notifier(Protocol):
    """Minimaler Notifier-Vertrag (nur fuer Typisierung)."""

    def notify(self, message: str) -> None: ...


class ImmediateActionResult:
    """Ergebnis einer Sofort-Massnahme."""

    def __init__(
        self,
        *,
        finding_id: str,
        category: ImmediateActionCategory,
        status: str,
        skipped: bool = False,
    ) -> None:
        self.finding_id = finding_id
        self.category = category
        self.status = status
        self.skipped = skipped

    def __repr__(self) -> str:
        return (
            f"ImmediateActionResult(finding_id={self.finding_id!r}, "
            f"category={self.category!r}, status={self.status!r}, "
            f"skipped={self.skipped!r})"
        )


class ImmediateActionService:
    """Fuehrt Sofort-Massnahmen aus und auditiert jede Aktion."""

    def __init__(
        self,
        audit_log: AuditWriter,
        notifier: Notifier | None = None,
    ) -> None:
        self._audit_log = audit_log
        self._notifier = notifier
        self._executed_finding_ids: set[str] = set()

    def execute(
        self,
        finding: Finding,
        category: ImmediateActionCategory,
    ) -> ImmediateActionResult:
        """Fuehrt die Sofort-Massnahme fuer das Finding aus.

        Idempotenz: Wurde fuer die finding_id bereits eine
        Aktion ausgefuehrt, wird KEIN Seiteneffekt ausgeloest,
        sondern ein Audit-Eintrag mit status=SKIPPED geschrieben.
        """
        finding_id = str(finding.id)

        if finding_id in self._executed_finding_ids:
            self._audit(
                finding=finding,
                category=category,
                status="SKIPPED",
            )
            return ImmediateActionResult(
                finding_id=finding_id,
                category=category,
                status="SKIPPED",
                skipped=True,
            )

        try:
            self._dispatch(finding, category)
        except PermissionError:
            self._audit(
                finding=finding,
                category=category,
                status="FAILED",
            )
            raise
        except Exception:
            self._audit(
                finding=finding,
                category=category,
                status="FAILED",
            )
            raise

        self._executed_finding_ids.add(finding_id)
        self._audit(
            finding=finding,
            category=category,
            status="SUCCESS",
        )
        return ImmediateActionResult(
            finding_id=finding_id,
            category=category,
            status="SUCCESS",
        )

    def _dispatch(
        self,
        finding: Finding,
        category: ImmediateActionCategory,
    ) -> None:
        if category == ImmediateActionCategory.BLOCK:
            self._do_block(finding)
        elif category == ImmediateActionCategory.ISOLATE:
            self._do_isolate(finding)
        elif category == ImmediateActionCategory.ALERT:
            self._do_alert(finding)
        elif category == ImmediateActionCategory.LOG_ONLY:
            self._do_log_only(finding)
        else:
            raise ValueError(f"Unbekannte Kategorie: {category!r}")

    def _do_block(self, finding: Finding) -> None:
        """Stub: echte Firewall-Integration ist eigene Phase."""
        if not self._has_permission(finding):
            raise PermissionError(
                f"Keine Berechtigung fuer BLOCK (finding={finding.id})"
            )
        logger.info("BLOCK (Stub) fuer finding=%s", finding.id)

    def _do_isolate(self, finding: Finding) -> None:
        """Stub: echte Firewall-Integration ist eigene Phase."""
        if not self._has_permission(finding):
            raise PermissionError(
                f"Keine Berechtigung fuer ISOLATE (finding={finding.id})"
            )
        logger.info("ISOLATE (Stub) fuer finding=%s", finding.id)

    def _do_alert(self, finding: Finding) -> None:
        if self._notifier is not None:
            self._notifier.notify(
                f"ALERT: finding={finding.id} severity={finding.severity}"
            )
        logger.info("ALERT fuer finding=%s", finding.id)

    def _do_log_only(self, finding: Finding) -> None:
        logger.info("LOG_ONLY fuer finding=%s", finding.id)

    def _has_permission(self, finding: Finding) -> bool:
        """Berechtigungspruefung fuer BLOCK/ISOLATE.

        Ein Finding ohne actor/permission-Marker gilt als
        nicht berechtigt (fail closed).
        """
        actor = getattr(finding, "actor", None)
        if actor is None:
            return False
        permissions = getattr(actor, "permissions", None)
        if permissions is None:
            return False
        return "immediate_action.execute" in permissions

    def _audit(
        self,
        *,
        finding: Finding,
        category: ImmediateActionCategory,
        status: str,
    ) -> None:
        self._audit_log.log(
            agent="immediate_action_service",
            tool="immediate_action",
            policy_result="applied",
            permission_level=1,
            execution_status="ok",
            details={
                "finding_id": str(finding.id),
                "category": category.value
                if hasattr(category, "value")
                else str(category),
                "status": status,
            },
        )