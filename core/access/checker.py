"""
AccessChecker: Berechtigungspruefung fuer Principals.

Zentrale Stelle, an der aus Principal + Rolle + Permissions eine
Ja/Nein-Entscheidung wird.

Regeln (fail closed):
- Principal unbekannt -> AccessDeniedError.
- Principal is_active False -> AccessDeniedError.
- Rolle hat Permission nicht -> AccessDeniedError.
- Permission-Code unbekannt (nicht in DB) -> AccessDeniedError.
- Kein Wildcard, kein Prefix-Match. Nur exakte Codes.

Aufrufer (Services) sollen require_permission() nutzen, nicht
has_permission() — damit der Pfad fail closed ist.
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
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._principals = PrincipalRepository(conn)
        self._roles = RoleRepository(conn)
        self._permissions = PermissionRepository(conn)
        # Cache pro Checker-Instanz (pro Request, nicht global).
        self._perm_cache: dict[int, frozenset[str]] = {}

    # ------------------------------------------------------------------ #
    # interne Helfer
    # ------------------------------------------------------------------ #

    def _role_permissions(self, role_id: int) -> frozenset[str]:
        cached = self._perm_cache.get(role_id)
        if cached is not None:
            return cached
        role = self._roles.get_by_id(role_id)
        codes = frozenset(role.permissions)
        self._perm_cache[role_id] = codes
        return codes

    # ------------------------------------------------------------------ #
    # oeffentliche API
    # ------------------------------------------------------------------ #

    def has_permission(self, principal_name: str, code: str) -> bool:
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

    def require_permission(self, principal_name: str, code: str) -> None:
        """
        Wie has_permission, aber wirft AccessDeniedError.
        Nutze diese Methode in Services.
        """
        if not self.has_permission(principal_name, code):
            raise AccessDeniedError(
                f"Zugriff verweigert: principal={principal_name!r} "
                f"permission={code!r}"
            )

    def role_of(self, principal_name: str) -> str:
        """Liefert den Rollennamen. Fehler -> AccessDeniedError."""
        try:
            p = self._principals.get_by_name(principal_name)
        except AccessNotFoundError as exc:
            raise AccessDeniedError(
                f"Principal {principal_name!r} nicht gefunden"
            ) from exc
        try:
            return self._roles.get_by_id(p.role_id).name
        except AccessNotFoundError as exc:
            raise AccessDeniedError(
                f"Rolle zu Principal {principal_name!r} nicht gefunden"
            ) from exc

    def permissions_of(self, principal_name: str) -> frozenset[str]:
        """
        Alle Permissions des Principals (aus der Rolle).
        Fehler -> AccessDeniedError.
        """
        try:
            p = self._principals.get_by_name(principal_name)
        except AccessNotFoundError as exc:
            raise AccessDeniedError(
                f"Principal {principal_name!r} nicht gefunden"
            ) from exc
        if not p.is_active:
            raise AccessDeniedError(
                f"Principal {principal_name!r} ist inaktiv"
            )
        return self._role_permissions(p.role_id)


__all__ = [
    "AccessChecker",
    "AccessDeniedError",
]
