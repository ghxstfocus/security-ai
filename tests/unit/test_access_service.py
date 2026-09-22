"""
Tests fuer core/services/access_service.py.

Auflage 37: SessionRepository ist Pflicht-Parameter.
- session_repo=None -> AccessServiceError.
- session_repo fehlt (keyword-only) -> TypeError.
- from_conn baut SessionRepository(conn) intern.

Auflage 39: from_conn nutzt dieselbe conn.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from core.access.checker import AccessChecker
from core.access.repository import (
    PermissionRepository,
    PrincipalRepository,
    RolePermissionRepository,
    RoleRepository,
)
from core.access.session_repo import SessionRepository
from core.inventory.repository import (
    DEFAULT_MIGRATIONS_DIR,
    apply_migrations,
    connect,
)
from core.services.access_service import (
    AccessService,
    AccessServiceError,
)
from harness.audit.writer import AuditWriter


# ---------------------------------------------------------------------- #
# Fixtures
# ---------------------------------------------------------------------- #

@pytest.fixture()
def conn(tmp_path: Path) -> sqlite3.Connection:
    db_path = tmp_path / "test.db"
    c = connect(db_path)
    apply_migrations(c, DEFAULT_MIGRATIONS_DIR)
    yield c
    c.close()


@pytest.fixture()
def audit(tmp_path: Path) -> AuditWriter:
    return AuditWriter(base_dir=tmp_path / "audit")


@pytest.fixture()
def deps(conn: sqlite3.Connection) -> dict:
    principals = PrincipalRepository(conn)
    roles = RoleRepository(conn)
    perms = PermissionRepository(conn)
    rp = RolePermissionRepository(conn)
    checker = AccessChecker(principals, roles, perms)
    return {
        "principals": principals,
        "roles": roles,
        "perms": perms,
        "role_perms": rp,
        "checker": checker,
    }


# ---------------------------------------------------------------------- #
# Auflage 37: session_repo ist Pflicht
# ---------------------------------------------------------------------- #

def test_session_repo_none_raises(
    deps: dict, audit: AuditWriter,
) -> None:
    with pytest.raises(AccessServiceError):
        AccessService(
            deps["principals"], deps["roles"], deps["perms"],
            deps["role_perms"], deps["checker"], audit,
            session_repo=None,  # type: ignore[arg-type]
        )


def test_session_repo_missing_raises_type_error(
    deps: dict, audit: AuditWriter,
) -> None:
    with pytest.raises(TypeError):
        AccessService(  # type: ignore[call-arg]
            deps["principals"], deps["roles"], deps["perms"],
            deps["role_perms"], deps["checker"], audit,
        )


def test_from_conn_builds_session_repo(
    conn: sqlite3.Connection, audit: AuditWriter,
) -> None:
    svc = AccessService.from_conn(conn, audit)
    assert isinstance(svc._session_repo, SessionRepository)
    # Auflage 39: dieselbe conn
    assert svc._session_repo._conn is conn


def test_explicit_session_repo_accepted(
    deps: dict, audit: AuditWriter,
    conn: sqlite3.Connection,
) -> None:
    session_repo = SessionRepository(conn)
    svc = AccessService(
        deps["principals"], deps["roles"], deps["perms"],
        deps["role_perms"], deps["checker"], audit,
        session_repo=session_repo,
    )
    assert svc._session_repo is session_repo
