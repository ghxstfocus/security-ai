# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AccessChecker: zentrale RBAC-Stelle.

Lese-Operationen (Check, Rolle, Permissions) und die
Durchsetzung (require_permission) liegen hier.
Schreibende Verwaltung liegt im AccessService.

Design:
- Konstruktor nimmt Repositories (DI). Aufrufer baut sie aus
  der Connection.
- from_conn(conn) als Convenience fuer einfache Aufrufer.
- Fail closed:
    check / require_permission -> False / AccessDeniedError
    role_of                     -> None bei unbekannt/inaktiv
    permissions_of              -> leeres frozenset
- Kein Wildcard, kein Prefix-Match. Nur exakte Codes.

Regel: Lesen -> Checker, Schreiben -> Service.
"""
from __future__ import annotations

import sqlite3

from core.access.repository import (
    AccessNotFoundError,
    PermissionRepository,
    PrincipalRepository,
    RoleRepository,
)


class AccessDeniedError(RuntimeError):
    """Berechtigung fehlt oder Principal ungueltig."""


class AccessChecker:
    def __init__(
        self,
        principal_repo: PrincipalRepository,
        role_repo: RoleRepository,
        permission_repo: PermissionRepository,
    ) -> None:
        self._principals = principal_repo
        self._roles = role_repo
        self._permissions = permission_repo
        # Cache pro Checker-Instanz (pro Request, nicht global).
        self._perm_cache: dict[int, frozenset[str]] = {}

    # ------------------------------------------------------------------ #
    # Konstruktor-Helfer
    # ------------------------------------------------------------------ #

    @classmethod
    def from_conn(cls, conn: sqlite3.Connection) -> AccessChecker:
        """Convenience: baut Repositories aus der Connection."""
        return cls(
            PrincipalRepository(conn),
            RoleRepository(conn),
            PermissionRepository(conn),
        )

    # ------------------------------------------------------------------ #
    # interne Helfer
    # ------------------------------------------------------------------ #

    def _role_permissions(self, role_id: int) -> frozenset[str]:
        cached = self._perm_cache.get(role_id)
        if cached is not None:
            return cached
        try:
            role = self._roles.get_by_id(role_id)
        except AccessNotFoundError:
            return frozenset()
        codes = frozenset(role.permissions)
        self._perm_cache[role_id] = codes
        return codes

    # ------------------------------------------------------------------ #
    # oeffentliche API
    # ------------------------------------------------------------------ #

    def check(self, principal_name: str, code: str) -> bool:
        """
        True nur, wenn:
        - principal existiert,
        - principal is_active,
        - Rolle die Permission hat,
        - Permission-Code in der DB existiert.
        Jeder Fehler -> False (fail closed, kein raise).
        """
        if not isinstance(principal_name, str) or not principal_name:
            return False
        if not isinstance(code, str) or not code:
            return False

        try:
            principal = self._principals.get_by_name(principal_name)
        except AccessNotFoundError:
            return False

        if not principal.is_active:
            return False

        try:
            self._permissions.get_by_code(code)
        except AccessNotFoundError:
            return False

        perms = self._role_permissions(principal.role_id)
        return code in perms

    # Rueckwaerts-kompatibler Name.
    def has_permission(self, principal_name: str, code: str) -> bool:
        return self.check(principal_name, code)

    def require_permission(self, principal_name: str, code: str) -> None:
        """
        Wie check, aber wirft AccessDeniedError.
        Nutze diese Methode in Services.
        """
        if not self.check(principal_name, code):
            raise AccessDeniedError(
                f"Zugriff verweigert: principal={principal_name!r} "
                f"permission={code!r}"
            )

    def role_of(self, principal_name: str) -> str | None:
        """
        Rollenname des Principals. None bei unbekannt/inaktiv.
        Kein raise.
        """
        if not isinstance(principal_name, str) or not principal_name:
            return None
        try:
            p = self._principals.get_by_name(principal_name)
        except AccessNotFoundError:
            return None
        if not p.is_active:
            return None
        try:
            return self._roles.get_by_id(p.role_id).name
        except AccessNotFoundError:
            return None

    def permissions_of(self, principal_name: str) -> frozenset[str]:
        """
        Alle Permissions des Principals. Leeres Set bei
        unbekannt/inaktiv. Kein raise.
        """
        if not isinstance(principal_name, str) or not principal_name:
            return frozenset()
        try:
            p = self._principals.get_by_name(principal_name)
        except AccessNotFoundError:
            return frozenset()
        if not p.is_active:
            return frozenset()
        return self._role_permissions(p.role_id)


__all__ = [
    "AccessChecker",
    "AccessDeniedError",
]
