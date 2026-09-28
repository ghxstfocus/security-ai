"""
AccessService: Service-Schicht fuer RBAC.

Duenne Fassade ueber AccessChecker, RoleRepository,
PermissionRepository, PrincipalRepository.

Aufgabe:
- Berechtigung pruefen (require_permission).
- Audit fuer jede schreibende Aktion.
- Rolle/Permission/Principal-Verwaltung.

Design:
- Kein UI-Code. Web, CLI, Telegram rufen denselben Service.
- Audit ist Pflicht bei Schreib-Aktionen (fail closed: wenn
  AuditWriter fehlt, wirft der Service).
- Der Service entscheidet nicht ueber Policy, nur ueber RBAC.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from core.access.checker import AccessChecker, AccessDeniedError
from core.access.models import (
    Permission,
    Principal,
    PrincipalKind,
    Role,
    hash_password,
    utc_now,
)
from core.access.repository import (
    AccessNotFoundError,
    AccessRepositoryError,
    PermissionRepository,
    PrincipalRepository,
    RolePermissionRepository,
    RoleRepository,
)
from core.access.session_repo import SessionRepository
from core.services import ServiceError
from harness.audit.writer import AuditWriter

AGENT = "security_ai"
TOOL = "access_service"

MIN_PASSWORD_LEN = 12


class AccessServiceError(ServiceError):
    """Fachlicher Fehler im AccessService."""


class AccessService:
    def __init__(
        self,
        principal_repo: PrincipalRepository,
        role_repo: RoleRepository,
        permission_repo: PermissionRepository,
        role_permission_repo: RolePermissionRepository,
        checker: AccessChecker,
        audit_writer: AuditWriter,
        *,
        session_repo: SessionRepository,
    ) -> None:
        if audit_writer is None:
            raise AccessServiceError(
                "audit_writer ist Pflicht (fail closed)"
            )
        if checker is None:
            raise AccessServiceError(
                "checker ist Pflicht (fail closed)"
            )
        if session_repo is None:
            raise AccessServiceError(
                "session_repo ist Pflicht (fail closed, "
                "Auflage 19)"
            )
        self._principals = principal_repo
        self._roles = role_repo
        self._perms = permission_repo
        self._role_perms = role_permission_repo
        self._checker = checker
        self._audit = audit_writer
        self._session_repo = session_repo

    @classmethod
    def from_conn(
        cls,
        conn: sqlite3.Connection,
        audit_writer: AuditWriter,
    ) -> AccessService:
        """Convenience: baut Repos + Checker aus der Connection."""
        principals = PrincipalRepository(conn)
        roles = RoleRepository(conn)
        perms = PermissionRepository(conn)
        rp = RolePermissionRepository(conn)
        checker = AccessChecker(principals, roles, perms)
        session_repo = SessionRepository(conn)
        return cls(
            principals, roles, perms, rp, checker, audit_writer,
            session_repo=session_repo,
        )

    # ------------------------------------------------------------------ #
    # Audit
    # ------------------------------------------------------------------ #

    def _log(self, kind: str, **extra: Any) -> None:
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

    # ------------------------------------------------------------------ #
    # Lesen (mit Berechtigung)
    # ------------------------------------------------------------------ #

    def require(self, principal_name: str, code: str) -> None:
        """Kurzform fuer self._checker.require_permission."""
        self._checker.require_permission(principal_name, code)

    def list_roles(self, actor: str) -> list[Role]:
        """
        list_roles: role.manage ODER principal.manage.
        Begruendung: Principals anlegen erfordert
        Rollen-Kenntnis (Auflage 147, 168).
        """
        if not (
            self._checker.check(actor, "role.manage")
            or self._checker.check(actor, "principal.manage")
        ):
            self.require(actor, "role.manage")
        return self._roles.list_all()

    def list_permissions(self, actor: str) -> list[Permission]:
        self.require(actor, "role.manage")
        return self._perms.list_all()

    def list_principals(self, actor: str) -> list[Principal]:
        self.require(actor, "principal.manage")
        return self._principals.list_all()

    def get_role(self, actor: str, name: str) -> Role:
        self.require(actor, "role.manage")
        return self._roles.get_by_name(name)

    def get_principal(self, actor: str, name: str) -> Principal:
        self.require(actor, "principal.manage")
        return self._principals.get_by_name(name)

    # ------------------------------------------------------------------ #
    # Schreiben (mit Berechtigung + Audit)
    # ------------------------------------------------------------------ #

    def create_principal(
        self,
        actor: str,
        *,
        name: str,
        role_name: str,
        kind: PrincipalKind = PrincipalKind.HUMAN,
        is_active: bool = True,
    ) -> Principal:
        """
        Legt einen Principal ohne Passwort an.
        Passwort setzen ist ein eigener Schritt (set_password),
        damit die Laengenpruefung greift (Auflage 153).
        """
        self.require(actor, "principal.manage")
        try:
            role = self._roles.get_by_name(role_name)
        except AccessNotFoundError as exc:
            raise AccessServiceError(
                f"Rolle {role_name!r} nicht gefunden"
            ) from exc
        # Auflage 597-602: Jeder Principal, der sich
        # einloggen koennen soll, braucht eine Rolle
        # mit device.read. Fail closed beim Anlegen
        # (nicht erst beim Login).
        if not role.has_permission("device.read"):
            raise AccessServiceError(
                f"Rolle {role_name!r} hat kein device.read. "
                f"Principal kann sich nicht einloggen."
            )
        if role.row_id is None:
            raise AccessServiceError(
                f"Rolle '{role_name}' ist nicht persistiert."
            )
        try:
            p = self._principals.create(
                name=name,
                role_id=role.row_id,
                kind=kind,
                password_hash=None,
                is_active=is_active,
            )
        except AccessRepositoryError as exc:
            raise AccessServiceError(str(exc)) from exc
        self._log(
            "principal_created",
            actor=actor,
            name=p.name,
            role=role.name,
            principal_kind=p.kind.value,
        )
        return p

    def set_principal_active(
        self,
        actor: str,
        *,
        name: str,
        is_active: bool,
    ) -> Principal:
        self.require(actor, "principal.manage")
        try:
            p = self._principals.set_active(name, is_active)
        except AccessNotFoundError as exc:
            raise AccessServiceError(str(exc)) from exc
        self._log(
            "principal_active_changed",
            actor=actor,
            name=p.name,
            is_active=p.is_active,
        )
        return p

    def set_password(
        self,
        actor: str,
        *,
        name: str,
        password: str,
    ) -> Principal:
        """
        Setzt ein neues Passwort fuer einen Principal.

        Sicherheitsverhalten (Auflage 14):
        - RBAC: actor braucht principal.manage.
        - Hash: pbkdf2_sha256, 600_000 Iterationen
          (Default von hash_password).
        - Alle aktiven Sessions des Principals werden
          widerrufen (Session-Invalidierung bei
          Passwort-Aenderung).
        - Audit: kind="principal_password_changed".
          NIEMALS Passwort, Hash oder Klartext in den
          Details.

        Raises:
            AccessDeniedError: actor ohne principal.manage.
            AccessServiceError: Principal unbekannt.
            SessionRepositoryError: Session-Invalidierung
                fehlgeschlagen. Passwort ist dann bereits
                geaendert; der Aufrufer MUSS den Fehler
                an den Nutzer melden.
        """
        self.require(actor, "principal.manage")
        if not isinstance(password, str):
            raise AccessServiceError(
                "Passwort muss String sein"
            )
        if len(password) < MIN_PASSWORD_LEN:
            raise AccessServiceError(
                f"Passwort zu kurz (min {MIN_PASSWORD_LEN})"
            )
        hashed = hash_password(password)
        try:
            p = self._principals.set_password_hash(name, hashed)
        except AccessNotFoundError as exc:
            raise AccessServiceError(str(exc)) from exc
        self._session_repo.revoke_all_for_principal(
            name, now=utc_now(),
        )
        self._log(
            "principal_password_changed",
            actor=actor,
            principal=p.name,
        )
        return p

    def assign_permission(
        self,
        actor: str,
        *,
        role_name: str,
        permission_code: str,
    ) -> None:
        self.require(actor, "role.manage")
        try:
            self._role_perms.assign(role_name, permission_code)
        except AccessNotFoundError as exc:
            raise AccessServiceError(str(exc)) from exc
        self._log(
            "permission_assigned",
            actor=actor,
            role=role_name,
            permission=permission_code,
        )

    def revoke_permission(
        self,
        actor: str,
        *,
        role_name: str,
        permission_code: str,
    ) -> int:
        self.require(actor, "role.manage")
        n = self._role_perms.revoke(role_name, permission_code)
        self._log(
            "permission_revoked",
            actor=actor,
            role=role_name,
            permission=permission_code,
            affected=n,
        )
        return n

    # ------------------------------------------------------------------ #
    # Selbst-Auskunft (jeder Principal darf das fuer sich)
    # ------------------------------------------------------------------ #

    def whoami(self, principal_name: str) -> dict[str, Any]:
        """
        Rolle und Permissions eines Principals.
        Keine Berechtigung noetig ausser: Principal existiert und
        ist aktiv.
        """
        role_name = self._checker.role_of(principal_name)
        perms = self._checker.permissions_of(principal_name)
        return {
            "principal": principal_name,
            "role": role_name,
            "permissions": sorted(perms),
        }


__all__ = [
    "MIN_PASSWORD_LEN",
    "AccessDeniedError",
    "AccessService",
    "AccessServiceError",
]
