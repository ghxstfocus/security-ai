"""
ChangeService: Service-Schicht fuer Change Requests.

Kapselt ChangeRepository hinter RBAC. Der Web-Layer
(apps/dashboard/routes_changes.py) darf NICHT direkt auf
das Repository zugreifen (DESIGN_DECISIONS §11).

Hinweis zum Audit (K3, Reviewer-Auflage):
- Es gibt KEINE harness/-Fassade fuer Changes. Audit wird
  hier im Service geschrieben, TOOL="change_service".
- Die CLI (scripts/changes_cli.py) schreibt denselben
  Kind-Namen "change_created" mit TOOL="changes_cli".
  Gleicher Kind, unterschiedliches TOOL = bewusst: der
  Nachweis "wer hat angelegt" trennt Web von CLI.
- Wer die CLI spaeter auf den Service umbaut, sieht den
  gleichen Kind-Namen mit TOOL="change_service". Das ist
  beabsichtigt, kein Bug.

Design:
- RBAC: change.view fuer Lesen, change.create fuer Anlegen.
- Audit bei create: kind="change_created", AGENT="security_ai",
  TOOL="change_service". NUR nicht-sensitive Felder:
  change_id, type, title (max 100 Zeichen), requested_by.
  KEIN description, diff_or_patch, rollback_plan, test_plan,
  files_affected (Auflage 58).
- Fail closed: repo/checker/audit_writer None -> Fehler.
- Laengengrenzen als Modul-Konstanten (Auflage 55).
  Begruendung (Auflage 54, Migration 0004 nutzt TEXT ohne
  CHECK):
    title 200          = ein Satz, den ein Mensch liest.
    description 2000   = Standard-Freitext.
    diff_or_patch 20000= gross genug fuer einen Patch,
                         klein genug gegen POST-DoS.
    rollback_plan 2000 = wie description.
    test_plan 2000     = wie description.
    files 50 x 500     = selten mehr als 50 Dateien
                         betroffen, 500 Zeichen pro Pfad.
- files_affected: heute reiner Text, kein Pfad. Kein
  Dateisystem-Zugriff (Auflage 57).
- Fehlerklassen (Auflage K1):
    ChangeServiceError   (ServiceError)    -> 400 Format.
    ChangeOperationError (OperationError)  -> 500 Betrieb
    (DB, Audit). Erbt NICHT von ChangeServiceError, damit
    der Route-Handler den Betriebsfehler nicht faengt.
"""
from __future__ import annotations

import re

from core.access.checker import AccessChecker
from core.changes.models import ChangeType
from core.changes.repository import (
    ChangeNotFoundError,
    ChangeRepository,
    ChangeRepositoryError,
)
from core.services import OperationError, ServiceError
from harness.audit.writer import AuditWriter

CHANGE_ID_RE = re.compile(r"^CHG-\d{4}-\d{5}$")

TITLE_MIN = 1
TITLE_MAX = 200
DESCRIPTION_MIN = 1
DESCRIPTION_MAX = 2000
DIFF_MAX = 20000
ROLLBACK_MAX = 2000
TEST_PLAN_MAX = 2000
FILES_MAX_ENTRIES = 50
FILE_PATH_MAX = 500
AUDIT_TITLE_MAX = 100

AGENT = "security_ai"
TOOL = "change_service"

VALID_TYPES = tuple(t.value for t in ChangeType)


class ChangeServiceError(ServiceError):
    """Fachlicher/Format-Fehler im ChangeService (4xx)."""


class ChangeOperationError(OperationError):
    """Betriebsfehler im ChangeService (5xx)."""


class ChangeService:
    def __init__(
        self,
        repo: ChangeRepository,
        checker: AccessChecker,
        audit_writer: AuditWriter,
    ) -> None:
        if repo is None:
            raise ChangeOperationError(
                "repo ist Pflicht (fail closed)"
            )
        if checker is None:
            raise ChangeOperationError(
                "checker ist Pflicht (fail closed)"
            )
        if audit_writer is None:
            raise ChangeOperationError(
                "audit_writer ist Pflicht (fail closed)"
            )
        self._repo = repo
        self._checker = checker
        self._audit = audit_writer

    def _require(self, actor: str, code: str) -> None:
        self._checker.require_permission(actor, code)

    def _log(self, kind: str, **extra) -> None:
        details = {"kind": kind}
        details.update(extra)
        self._audit.log(
            agent=AGENT,
            tool=TOOL,
            policy_result="ALLOWED",
            permission_level=0,
            execution_status="OK",
            details=details,
        )

    def _validate_change_id(self, change_id: object) -> str:
        if not isinstance(change_id, str):
            raise ChangeServiceError("change_id muss String sein")
        if not CHANGE_ID_RE.match(change_id):
            raise ChangeServiceError("change_id ungueltig")
        return change_id

    def _validate_len(
        self, name: str, value, *, min_len: int, max_len: int,
        required: bool = True,
    ) -> str | None:
        if value is None:
            if required:
                raise ChangeServiceError(f"{name} fehlt")
            return None
        if not isinstance(value, str):
            raise ChangeServiceError(f"{name} muss String sein")
        if len(value) < min_len:
            raise ChangeServiceError(
                f"{name} zu kurz (min {min_len})"
            )
        if len(value) > max_len:
            raise ChangeServiceError(
                f"{name} zu lang (max {max_len})"
            )
        return value

    def _parse_files_affected(
        self, raw: str | None,
    ) -> list[str] | None:
        if raw is None:
            return None
        if not isinstance(raw, str):
            raise ChangeServiceError(
                "files_affected muss String sein"
            )
        lines = [ln.strip() for ln in raw.splitlines()]
        lines = [ln for ln in lines if ln]
        if not lines:
            return None
        if len(lines) > FILES_MAX_ENTRIES:
            raise ChangeServiceError(
                f"files_affected zu viele Eintraege "
                f"(max {FILES_MAX_ENTRIES})"
            )
        for ln in lines:
            if len(ln) > FILE_PATH_MAX:
                raise ChangeServiceError(
                    f"files_affected: Eintrag zu lang "
                    f"(max {FILE_PATH_MAX})"
                )
        return lines

    def list_all(self, actor: str) -> list[dict]:
        """Lesen, kein Audit (§11)."""
        self._require(actor, "change.view")
        return [r.to_dict() for r in self._repo.list_all()]

    def get(self, actor: str, change_id: str) -> dict | None:
        self._require(actor, "change.view")
        cid = self._validate_change_id(change_id)
        try:
            return self._repo.get(cid).to_dict()
        except ChangeNotFoundError:
            return None

    def create(
        self,
        actor: str,
        *,
        title: str,
        description: str,
        type: str,
        diff_or_patch: str | None = None,
        files_affected: str | None = None,
        rollback_plan: str | None = None,
        test_plan: str | None = None,
    ) -> dict:
        self._require(actor, "change.create")

        t = self._validate_len(
            "title", title,
            min_len=TITLE_MIN, max_len=TITLE_MAX,
        )
        d = self._validate_len(
            "description", description,
            min_len=DESCRIPTION_MIN, max_len=DESCRIPTION_MAX,
        )
        if not isinstance(type, str) or type not in VALID_TYPES:
            raise ChangeServiceError("type ungueltig")
        dp = self._validate_len(
            "diff_or_patch", diff_or_patch,
            min_len=0, max_len=DIFF_MAX, required=False,
        )
        rp = self._validate_len(
            "rollback_plan", rollback_plan,
            min_len=0, max_len=ROLLBACK_MAX, required=False,
        )
        tp = self._validate_len(
            "test_plan", test_plan,
            min_len=0, max_len=TEST_PLAN_MAX, required=False,
        )
        files = self._parse_files_affected(files_affected)

        try:
            req = self._repo.create(
                title=t,
                description=d,
                requested_by=actor,
                type=ChangeType(type),
                diff_or_patch=dp,
                files_affected=files,
                rollback_plan=rp,
                test_plan=tp,
            )
        except ChangeRepositoryError as exc:
            raise ChangeOperationError(
                f"Anlegen fehlgeschlagen: {exc}"
            ) from exc

        title_for_audit = t[:AUDIT_TITLE_MAX]
        try:
            self._log(
                "change_created",
                change_id=req.change_id,
                type=req.type.value,
                title=title_for_audit,
                requested_by=actor,
            )
        except Exception as exc:
            # DB-Eintrag bleibt (kein Rollback). Audit-Fehler ist
            # Betriebsproblem, der Nutzer muss das merken (K2).
            raise ChangeOperationError(
                f"Audit fehlgeschlagen: {exc}"
            ) from exc

        return req.to_dict()


__all__ = [
    "AGENT",
    "AUDIT_TITLE_MAX",
    "CHANGE_ID_RE",
    "DESCRIPTION_MAX",
    "DIFF_MAX",
    "FILES_MAX_ENTRIES",
    "FILE_PATH_MAX",
    "ROLLBACK_MAX",
    "TEST_PLAN_MAX",
    "TITLE_MAX",
    "TOOL",
    "VALID_TYPES",
    "ChangeOperationError",
    "ChangeService",
    "ChangeServiceError",
]
