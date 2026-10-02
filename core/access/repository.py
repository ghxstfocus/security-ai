# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Repositories fuer RBAC.

Konvention wie DeviceRepository / ApprovalRepository:
- Der Konstruktor bekommt eine offene sqlite3.Connection.
- connect/apply_migrations/close liegen beim Aufrufer.
- row_factory = sqlite3.Row wird defensiv sichergestellt.

Repositories:
- RoleRepository
- PermissionRepository
- RolePermissionRepository
- PrincipalRepository
"""
from __future__ import annotations

import sqlite3

from core.access.models import (
    Permission,
    Principal,
    PrincipalKind,
    Role,
    utc_now_iso,
)


class AccessRepositoryError(RuntimeError):
    """Fachlicher Fehler im Access-Repository."""


class AccessNotFoundError(AccessRepositoryError):
    """Objekt existiert nicht."""


def _ensure_row_factory(conn: sqlite3.Connection) -> None:
    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row


# ---------------------------------------------------------------------- #
# Permissions
# ---------------------------------------------------------------------- #

class PermissionRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        _ensure_row_factory(conn)

    def list_all(self) -> list[Permission]:
        cur = self._conn.execute(
            "SELECT id, code, description FROM permissions "
            "ORDER BY code ASC"
        )
        return [Permission.from_row(r) for r in cur.fetchall()]

    def get_by_code(self, code: str) -> Permission:
        if not isinstance(code, str) or not code:
            raise AccessRepositoryError("code darf nicht leer sein")
        cur = self._conn.execute(
            "SELECT id, code, description FROM permissions WHERE code = ?",
            (code,),
        )
        row = cur.fetchone()
        if row is None:
            raise AccessNotFoundError(
                f"Permission {code!r} nicht gefunden"
            )
        return Permission.from_row(row)


# ---------------------------------------------------------------------- #
# Roles
# ---------------------------------------------------------------------- #

class RoleRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        _ensure_row_factory(conn)

    def _permissions_of(self, role_id: int) -> tuple[str, ...]:
        cur = self._conn.execute(
            "SELECT p.code FROM role_permissions rp "
            "JOIN permissions p ON p.id = rp.permission_id "
            "WHERE rp.role_id = ? "
            "ORDER BY p.code ASC",
            (role_id,),
        )
        return tuple(r["code"] for r in cur.fetchall())

    def list_all(self) -> list[Role]:
        cur = self._conn.execute(
            "SELECT id, name, description, created_at FROM roles "
            "ORDER BY name ASC"
        )
        return [
            Role.from_row(r, permissions=self._permissions_of(r["id"]))
            for r in cur.fetchall()
        ]

    def get_by_name(self, name: str) -> Role:
        if not isinstance(name, str) or not name:
            raise AccessRepositoryError("name darf nicht leer sein")
        cur = self._conn.execute(
            "SELECT id, name, description, created_at FROM roles "
            "WHERE name = ?",
            (name,),
        )
        row = cur.fetchone()
        if row is None:
            raise AccessNotFoundError(f"Role {name!r} nicht gefunden")
        return Role.from_row(
            row, permissions=self._permissions_of(row["id"])
        )

    def get_by_id(self, role_id: int) -> Role:
        cur = self._conn.execute(
            "SELECT id, name, description, created_at FROM roles "
            "WHERE id = ?",
            (role_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise AccessNotFoundError(
                f"Role id={role_id!r} nicht gefunden"
            )
        return Role.from_row(
            row, permissions=self._permissions_of(row["id"])
        )


# ---------------------------------------------------------------------- #
# Role <-> Permission
# ---------------------------------------------------------------------- #

class RolePermissionRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        _ensure_row_factory(conn)

    def assign(self, role_name: str, permission_code: str) -> None:
        cur = self._conn.execute(
            "INSERT OR IGNORE INTO role_permissions "
            "(role_id, permission_id) "
            "SELECT r.id, p.id FROM roles r, permissions p "
            "WHERE r.name = ? AND p.code = ?",
            (role_name, permission_code),
        )
        if (cur.rowcount or 0) == 0:
            # Entweder schon vorhanden oder unbekannt. Pruefen:
            has_role = self._conn.execute(
                "SELECT 1 FROM roles WHERE name = ?", (role_name,)
            ).fetchone()
            has_perm = self._conn.execute(
                "SELECT 1 FROM permissions WHERE code = ?",
                (permission_code,),
            ).fetchone()
            if not has_role:
                raise AccessNotFoundError(
                    f"Role {role_name!r} nicht gefunden"
                )
            if not has_perm:
                raise AccessNotFoundError(
                    f"Permission {permission_code!r} nicht gefunden"
                )
            # schon zugewiesen -> idempotent, kein Fehler
        self._conn.commit()

    def revoke(self, role_name: str, permission_code: str) -> int:
        cur = self._conn.execute(
            "DELETE FROM role_permissions "
            "WHERE role_id = (SELECT id FROM roles WHERE name = ?) "
            "AND permission_id = "
            "(SELECT id FROM permissions WHERE code = ?)",
            (role_name, permission_code),
        )
        n = cur.rowcount or 0
        self._conn.commit()
        return n


# ---------------------------------------------------------------------- #
# Principals
# ---------------------------------------------------------------------- #

class PrincipalRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        _ensure_row_factory(conn)

    def create(
        self,
        *,
        name: str,
        role_id: int,
        kind: PrincipalKind = PrincipalKind.HUMAN,
        password_hash: str | None = None,
        is_active: bool = True,
    ) -> Principal:
        if not isinstance(name, str) or not name.strip():
            raise AccessRepositoryError("name darf nicht leer sein")
        if not isinstance(role_id, int) or role_id <= 0:
            raise AccessRepositoryError("role_id muss positive int sein")
        if not isinstance(kind, PrincipalKind):
            raise AccessRepositoryError(
                "kind muss PrincipalKind sein"
            )
        if password_hash is not None and not isinstance(
                password_hash, str):
            raise AccessRepositoryError(
                "password_hash muss String oder None sein"
            )

        # Rolle existiert?
        row = self._conn.execute(
            "SELECT 1 FROM roles WHERE id = ?", (role_id,)
        ).fetchone()
        if row is None:
            raise AccessNotFoundError(
                f"Role id={role_id!r} nicht gefunden"
            )

        created = utc_now_iso()
        try:
            self._conn.execute(
                "INSERT INTO principals "
                "(name, kind, role_id, password_hash, is_active, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    name,
                    kind.value,
                    role_id,
                    password_hash,
                    1 if is_active else 0,
                    created,
                ),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            self._conn.rollback()
            raise AccessRepositoryError(
                f"Principal {name!r} existiert bereits"
            ) from exc

        return self.get_by_name(name)

    def get_by_name(self, name: str) -> Principal:
        if not isinstance(name, str) or not name:
            raise AccessRepositoryError("name darf nicht leer sein")
        cur = self._conn.execute(
            "SELECT id, name, kind, role_id, password_hash, "
            "is_active, created_at FROM principals WHERE name = ?",
            (name,),
        )
        row = cur.fetchone()
        if row is None:
            raise AccessNotFoundError(
                f"Principal {name!r} nicht gefunden"
            )
        return Principal.from_row(row)

    def list_all(self) -> list[Principal]:
        cur = self._conn.execute(
            "SELECT id, name, kind, role_id, password_hash, "
            "is_active, created_at FROM principals ORDER BY name ASC"
        )
        return [Principal.from_row(r) for r in cur.fetchall()]

    def set_active(self, name: str, is_active: bool) -> Principal:
        if not isinstance(is_active, bool):
            raise AccessRepositoryError("is_active muss bool sein")
        cur = self._conn.execute(
            "UPDATE principals SET is_active = ? WHERE name = ?",
            (1 if is_active else 0, name),
        )
        if (cur.rowcount or 0) == 0:
            self._conn.rollback()
            raise AccessNotFoundError(
                f"Principal {name!r} nicht gefunden"
            )
        self._conn.commit()
        return self.get_by_name(name)

    def set_password_hash(self, name: str, password_hash: str) -> Principal:
        if not isinstance(password_hash, str) or not password_hash:
            raise AccessRepositoryError(
                "password_hash darf nicht leer sein"
            )
        cur = self._conn.execute(
            "UPDATE principals SET password_hash = ? WHERE name = ?",
            (password_hash, name),
        )
        if (cur.rowcount or 0) == 0:
            self._conn.rollback()
            raise AccessNotFoundError(
                f"Principal {name!r} nicht gefunden"
            )
        self._conn.commit()
        return self.get_by_name(name)


__all__ = [
    "AccessNotFoundError",
    "AccessRepositoryError",
    "PermissionRepository",
    "PrincipalRepository",
    "RolePermissionRepository",
    "RoleRepository",
]
