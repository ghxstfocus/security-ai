"""
RBAC-Datenmodell.

Rollen, Permissions, Principals.

Konventionen:
- Alle Zeitstempel UTC-aware, ISO-8601-Strings.
- Dataclasses sind frozen (unveraenderlich).
- permission_code ist der stabile Schluessel (z. B. "chat.ask").
- role.name ist der stabile Schluessel (z. B. "admin").
"""
from __future__ import annotations

import hashlib
import hmac
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------- #
# Enums
# ---------------------------------------------------------------------- #

class PrincipalKind(str, Enum):
    """Art des Principals."""

    HUMAN = "human"
    SYSTEM = "system"
    SERVICE = "service"


# ---------------------------------------------------------------------- #
# Zeit-Helfer
# ---------------------------------------------------------------------- #

def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def require_utc_iso(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(
            f"{field_name} muss ISO-8601-String sein"
        )
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(
            f"{field_name} nicht parsebar: {value!r}"
        ) from exc
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(
            f"{field_name} muss timezone-aware sein"
        )
    return value


def _require_str(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} darf nicht leer sein")
    return value

def utc_now() -> datetime:
    """datetime, fuer timedelta-Rechnungen (nicht fuer Modelle)."""
    return datetime.now(UTC)


def to_utc(value: datetime | str) -> datetime:
    """
    Normalisiert datetime | str auf UTC-aware datetime.

    Regeln:
    - datetime mit tzinfo=None -> ValueError (fail closed).
    - datetime mit tzinfo != UTC -> auf UTC konvertiert.
    - str -> datetime.fromisoformat, muss tzinfo haben.
    """
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError(
                f"Zeit nicht parsebar: {value!r}"
            ) from exc
    elif isinstance(value, datetime):
        dt = value
    else:
        raise TypeError(
            f"Zeit muss datetime oder str sein, "
            f"nicht {type(value).__name__}"
        )
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError("Zeit muss timezone-aware sein")
    return dt.astimezone(UTC)


def to_iso(value: datetime | str) -> str:
    """Normalisiert auf UTC-aware ISO-8601-String."""
    return to_utc(value).isoformat()


# ---------------------------------------------------------------------- #
# Passwort-Hashing (pbkdf2_sha256, OWASP 2023)
# ---------------------------------------------------------------------- #

PBKDF2_ITERATIONS = 600_000
PBKDF2_SALT_BYTES = 16
PBKDF2_ALGO = "pbkdf2_sha256"


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS
                  ) -> str:
    """
    Hasht ein Passwort. Format:
        pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Passwort darf nicht leer sein")
    salt = os.urandom(PBKDF2_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return f"{PBKDF2_ALGO}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    """
    Prueft ein Passwort gegen einen gespeicherten Hash.
    Liefert False bei jedem Formatfehler (fail closed, kein raise).
    """
    if not isinstance(password, str) or not isinstance(encoded, str):
        return False
    try:
        algo, iters_s, salt_hex, hash_hex = encoded.split("$", 3)
        if algo != PBKDF2_ALGO:
            return False
        iters = int(iters_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iters
    )
    return hmac.compare_digest(candidate, expected)


# ---------------------------------------------------------------------- #
# Permission
# ---------------------------------------------------------------------- #

@dataclass(frozen=True)
class Permission:
    """Eine einzelne Berechtigung. code ist der stabile Schluessel."""

    code: str
    description: str | None = None
    row_id: int | None = None

    def __post_init__(self) -> None:
        _require_str(self.code, "Permission.code")

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> Permission:
        return cls(
            row_id=row["id"],
            code=row["code"],
            description=row["description"],
        )


# ---------------------------------------------------------------------- #
# Role
# ---------------------------------------------------------------------- #

@dataclass(frozen=True)
class Role:
    """Eine Rolle. name ist der stabile Schluessel."""

    name: str
    description: str | None = None
    created_at: str = ""
    permissions: tuple[str, ...] = field(default_factory=tuple)
    row_id: int | None = None

    def __post_init__(self) -> None:
        _require_str(self.name, "Role.name")
        if self.created_at:
            require_utc_iso(self.created_at, "Role.created_at")
        if not isinstance(self.permissions, tuple):
            raise TypeError("Role.permissions muss tuple sein")

    def has_permission(self, code: str) -> bool:
        return code in self.permissions

    @classmethod
    def from_row(cls, row: Mapping[str, Any],
                 permissions: tuple[str, ...] = ()) -> Role:
        return cls(
            row_id=row["id"],
            name=row["name"],
            description=row["description"],
            created_at=row["created_at"],
            permissions=permissions,
        )


# ---------------------------------------------------------------------- #
# Principal
# ---------------------------------------------------------------------- #

@dataclass(frozen=True)
class Principal:
    """
    Eine Entitaet, die authentifiziert werden kann.

    kind: human | system | service.
    password_hash NULL -> kein Login (z. B. cli-admin).
    is_active False -> gesperrt.
    """

    name: str
    role_id: int
    kind: PrincipalKind
    created_at: str
    password_hash: str | None = None
    is_active: bool = True
    row_id: int | None = None

    def __post_init__(self) -> None:
        _require_str(self.name, "Principal.name")
        if not isinstance(self.role_id, int):
            raise TypeError("Principal.role_id muss int sein")
        if self.role_id <= 0:
            raise ValueError("Principal.role_id muss positive sein")
        if not isinstance(self.kind, PrincipalKind):
            raise TypeError(
                f"Principal.kind muss PrincipalKind sein, "
                f"nicht {type(self.kind).__name__}"
            )
        require_utc_iso(self.created_at, "Principal.created_at")
        if not isinstance(self.is_active, bool):
            raise TypeError("Principal.is_active muss bool sein")
        if self.password_hash is not None and (not isinstance(self.password_hash, str) or \
                    not self.password_hash):
            raise ValueError(
                "Principal.password_hash muss String oder None sein"
            )

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> Principal:
        return cls(
            row_id=row["id"],
            name=row["name"],
            kind=PrincipalKind(row["kind"]),
            role_id=row["role_id"],
            password_hash=row["password_hash"],
            is_active=bool(row["is_active"]),
            created_at=row["created_at"],
        )


# ---------------------------------------------------------------------- #
# Session
# ---------------------------------------------------------------------- #

@dataclass(frozen=True)
class Session:
    """
    Eine serverseitige Session.

    id ist TEXT-Primary-Key (fachlich), kein row_id.
    revoked_at NULL -> aktiv.
    """

    id: str
    principal_name: str
    created_at: str
    last_seen_at: str
    revoked_at: str | None = None
    ip: str | None = None
    user_agent: str | None = None

    def __post_init__(self) -> None:
        _require_str(self.id, "Session.id")
        _require_str(self.principal_name, "Session.principal_name")
        require_utc_iso(self.created_at, "Session.created_at")
        require_utc_iso(self.last_seen_at, "Session.last_seen_at")
        if self.revoked_at is not None:
            require_utc_iso(self.revoked_at, "Session.revoked_at")

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> Session:
        return cls(
            id=row["id"],
            principal_name=row["principal_name"],
            created_at=row["created_at"],
            last_seen_at=row["last_seen_at"],
            revoked_at=row["revoked_at"],
            ip=row["ip"],
            user_agent=row["user_agent"],
        )


# ---------------------------------------------------------------------- #
# UI-Projektion fuer Principal
# ---------------------------------------------------------------------- #

def principal_to_view(principal: Principal) -> dict:
    """
    Projektion fuer die UI: nur die nicht-sensitiven Felder.

    Kein password_hash, kein row_id. has_password ist bool,
    nicht der Hash selbst (Auflage 143-146).
    """
    if principal is None:
        raise ValueError("principal darf nicht None sein")
    return {
        "name": principal.name,
        "kind": principal.kind.value,
        "role_id": principal.role_id,
        "is_active": principal.is_active,
        "has_password": bool(principal.password_hash),
        "created_at": principal.created_at,
    }


def role_to_view(role: Role) -> dict:
    """
    Projektion fuer die UI: nur die nicht-sensitiven Felder.
    permissions als sortierte Liste (nach code),
    damit die Anzeige stabil ist (Auflage 181).
    """
    if role is None:
        raise ValueError("role darf nicht None sein")
    return {
        "name": role.name,
        "description": role.description,
        "created_at": role.created_at,
        "permissions": sorted(role.permissions),
    }


def permission_to_view(permission: Permission) -> dict:
    """
    Projektion fuer die UI. Kein row_id (Auflage 182).
    """
    if permission is None:
        raise ValueError("permission darf nicht None sein")
    return {
        "code": permission.code,
        "description": permission.description,
    }


__all__ = [
    "PBKDF2_ITERATIONS",
    "Permission",
    "Principal",
    "PrincipalKind",
    "Role",
    "Session",
    "hash_password",
    "permission_to_view",
    "principal_to_view",
    "require_utc_iso",
    "role_to_view",
    "to_iso",
    "to_utc",
    "utc_now",
    "utc_now_iso",
    "verify_password",
]
