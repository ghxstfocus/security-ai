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
from core.access.models import PrincipalKind
from core.access.repository import (
    PermissionRepository,
    PrincipalRepository,
    RolePermissionRepository,
    RoleRepository,
)
from core.access.session_repo import SessionRepository
from core.services.access_service import (
    AccessService,
    AccessServiceError,
)
from harness.audit.writer import AuditWriter
from tests.unit._helpers import migrated_conn

# ---------------------------------------------------------------------- #
# Fixtures
# ---------------------------------------------------------------------- #

@pytest.fixture()
def conn(tmp_path: Path) -> sqlite3.Connection:
    c = migrated_conn(tmp_path)
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


# ---------------------------------------------------------------------- #
# Fixture fuer set_password-Tests
# ---------------------------------------------------------------------- #

@pytest.fixture()
def alice(deps: dict) -> dict:
    roles = deps["roles"]
    viewer = roles.get_by_name("viewer")
    principals = deps["principals"]
    p = principals.create(
        name="alice",
        role_id=viewer.row_id,
        kind=PrincipalKind.HUMAN,
        password_hash=None,
    )
    return {"principal": p, "role": viewer}


@pytest.fixture()
def alice_sessions(
    conn: sqlite3.Connection, alice: dict,
) -> SessionRepository:
    sr = SessionRepository(conn)
    sr.create("sid-alice-1", "alice")
    sr.create("sid-alice-2", "alice")
    return sr


# ---------------------------------------------------------------------- #
# set_password (Auflage 14, 42, 43, 44, 45)
# ---------------------------------------------------------------------- #

def test_set_password_requires_permission(
    deps: dict, audit: AuditWriter, conn: sqlite3.Connection,
    alice: dict,
) -> None:
    sr = SessionRepository(conn)
    svc = AccessService(
        deps["principals"], deps["roles"], deps["perms"],
        deps["role_perms"], deps["checker"], audit,
        session_repo=sr,
    )
    # alice hat Rolle viewer -> kein principal.manage
    with pytest.raises(Exception) as exc_info:
        svc.set_password("alice", name="alice", password="geheim123456")
    assert "principal.manage" in str(exc_info.value)


def test_set_password_updates_hash(
    deps: dict, audit: AuditWriter, conn: sqlite3.Connection,
    alice: dict,
) -> None:
    sr = SessionRepository(conn)
    svc = AccessService(
        deps["principals"], deps["roles"], deps["perms"],
        deps["role_perms"], deps["checker"], audit,
        session_repo=sr,
    )
    # cli-admin hat Rolle admin; alice anlegen mit admin-Rolle
    # fuer diesen Test brauchen wir einen actor mit principal.manage
    # -> nutze einen zweiten admin-Principal
    admin_role = deps["roles"].get_by_name("admin")
    deps["principals"].create(
        name="admin1",
        role_id=admin_role.row_id,
        kind=PrincipalKind.HUMAN,
    )
    svc.set_password("admin1", name="alice", password="geheim123456")
    updated = deps["principals"].get_by_name("alice")
    assert updated.password_hash is not None
    assert updated.password_hash.startswith("pbkdf2_sha256$600000$")


def test_set_password_revokes_sessions(
    deps: dict, audit: AuditWriter, conn: sqlite3.Connection,
    alice: dict, alice_sessions: SessionRepository,
) -> None:
    admin_role = deps["roles"].get_by_name("admin")
    deps["principals"].create(
        name="admin1", role_id=admin_role.row_id,
        kind=PrincipalKind.HUMAN,
    )
    svc = AccessService(
        deps["principals"], deps["roles"], deps["perms"],
        deps["role_perms"], deps["checker"], audit,
        session_repo=alice_sessions,
    )
    assert alice_sessions.get("sid-alice-1").revoked_at is None
    assert alice_sessions.get("sid-alice-2").revoked_at is None
    svc.set_password("admin1", name="alice", password="geheim123456")
    assert alice_sessions.get("sid-alice-1").revoked_at is not None
    assert alice_sessions.get("sid-alice-2").revoked_at is not None


def test_set_password_audit_kind(
    deps: dict, audit: AuditWriter, conn: sqlite3.Connection,
    alice: dict,
) -> None:
    admin_role = deps["roles"].get_by_name("admin")
    deps["principals"].create(
        name="admin1", role_id=admin_role.row_id,
        kind=PrincipalKind.HUMAN,
    )
    sr = SessionRepository(conn)
    svc = AccessService(
        deps["principals"], deps["roles"], deps["perms"],
        deps["role_perms"], deps["checker"], audit,
        session_repo=sr,
    )
    svc.set_password("admin1", name="alice", password="geheim123456")
    entries = audit.read_day()
    kinds = [
        e.details.get("kind") for e in entries if e.details
    ]
    assert "principal_password_changed" in kinds


def test_set_password_no_password_in_audit(
    deps: dict, audit: AuditWriter, conn: sqlite3.Connection,
    alice: dict,
) -> None:
    admin_role = deps["roles"].get_by_name("admin")
    deps["principals"].create(
        name="admin1", role_id=admin_role.row_id,
        kind=PrincipalKind.HUMAN,
    )
    sr = SessionRepository(conn)
    svc = AccessService(
        deps["principals"], deps["roles"], deps["perms"],
        deps["role_perms"], deps["checker"], audit,
        session_repo=sr,
    )
    svc.set_password("admin1", name="alice", password="geheim123456")
    updated = deps["principals"].get_by_name("alice")
    stored_hash = updated.password_hash
    # Audit-Tag lesen
    audit_path = audit.base_dir / (
        __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).strftime("%Y-%m-%d") + ".jsonl"
    )
    content = audit_path.read_text(encoding="utf-8")
    assert "geheim123456" not in content
    assert stored_hash is not None
    assert stored_hash not in content
    assert "pbkdf2_sha256$" not in content
    assert "pbkdf2_sha256" not in content


def test_set_password_unknown_principal(
    deps: dict, audit: AuditWriter, conn: sqlite3.Connection,
) -> None:
    admin_role = deps["roles"].get_by_name("admin")
    deps["principals"].create(
        name="admin1", role_id=admin_role.row_id,
        kind=PrincipalKind.HUMAN,
    )
    sr = SessionRepository(conn)
    svc = AccessService(
        deps["principals"], deps["roles"], deps["perms"],
        deps["role_perms"], deps["checker"], audit,
        session_repo=sr,
    )
    with pytest.raises(AccessServiceError):
        svc.set_password(
            "admin1", name="nichtda",
            password="nichtzu kurz12",
        )


def test_set_password_revoke_failure_propagates(
    deps: dict, audit: AuditWriter, conn: sqlite3.Connection,
    alice: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.access.session_repo import SessionRepositoryError

    admin_role = deps["roles"].get_by_name("admin")
    deps["principals"].create(
        name="admin1", role_id=admin_role.row_id,
        kind=PrincipalKind.HUMAN,
    )
    sr = SessionRepository(conn)

    def _boom(*args, **kwargs):
        raise SessionRepositoryError("simuliert")

    monkeypatch.setattr(
        sr, "revoke_all_for_principal", _boom,
    )

    svc = AccessService(
        deps["principals"], deps["roles"], deps["perms"],
        deps["role_perms"], deps["checker"], audit,
        session_repo=sr,
    )
    with pytest.raises(SessionRepositoryError):
        svc.set_password("admin1", name="alice", password="geheim123456")


# ---------------------------------------------------------------------- #
# Test 3.6.8: ServiceError-Hierarchie
# ---------------------------------------------------------------------- #

def test_access_service_error_is_service_error():
    from core.services import ServiceError
    assert issubclass(AccessServiceError, ServiceError)


# ---------------------------------------------------------------------- #
# 3.6.8f: MIN_PASSWORD_LEN (A151, A152, A171, A176, A177)
# ---------------------------------------------------------------------- #

def test_set_password_too_short(
    deps: dict, audit: AuditWriter, conn: sqlite3.Connection,
    alice: dict,
) -> None:
    admin_role = deps["roles"].get_by_name("admin")
    deps["principals"].create(
        name="admin1", role_id=admin_role.row_id,
        kind=PrincipalKind.HUMAN,
    )
    sr = SessionRepository(conn)
    svc = AccessService(
        deps["principals"], deps["roles"], deps["perms"],
        deps["role_perms"], deps["checker"], audit,
        session_repo=sr,
    )
    with pytest.raises(AccessServiceError):
        svc.set_password(
            "admin1", name="alice", password="kurz1234",
        )


def test_set_password_short_password_before_notfound(
    deps: dict, audit: AuditWriter, conn: sqlite3.Connection,
) -> None:
    """
    A177: Laengenpruefung greift VOR der DB-Abfrage.
    """
    admin_role = deps["roles"].get_by_name("admin")
    deps["principals"].create(
        name="admin1", role_id=admin_role.row_id,
        kind=PrincipalKind.HUMAN,
    )
    sr = SessionRepository(conn)
    svc = AccessService(
        deps["principals"], deps["roles"], deps["perms"],
        deps["role_perms"], deps["checker"], audit,
        session_repo=sr,
    )
    with pytest.raises(AccessServiceError):
        svc.set_password(
            "admin1", name="nichtda", password="x",
        )


# ---------------------------------------------------------------------- #
# 3.6.8f: list_roles mit principal.manage (A147, A169)
# ---------------------------------------------------------------------- #

def test_list_roles_with_principal_manage_only(
    deps: dict, audit: AuditWriter, conn: sqlite3.Connection,
) -> None:
    """Principal mit principal.manage (ohne role.manage)
    darf list_roles aufrufen."""
    from core.access.repository import RolePermissionRepository
    conn.execute(
        "INSERT INTO roles (name, description, created_at) "
        "VALUES (?, ?, ?)",
        (
            "principal_only",
            "Test-Rolle nur principal.manage",
            "2026-01-01T00:00:00+00:00",
        ),
    )
    conn.commit()
    rp = RolePermissionRepository(conn)
    rp.assign("principal_only", "principal.manage")
    role = deps["roles"].get_by_name("principal_only")
    deps["principals"].create(
        name="p1", role_id=role.row_id,
        kind=PrincipalKind.HUMAN,
    )
    sr = SessionRepository(conn)
    svc = AccessService(
        deps["principals"], deps["roles"], deps["perms"],
        deps["role_perms"], deps["checker"], audit,
        session_repo=sr,
    )
    roles = svc.list_roles("p1")
    assert isinstance(roles, list)
    assert any(r.name == "admin" for r in roles)

# ---------------------------------------------------------------------- #
# Punkt 3: create_principal erzwingt device.read (A597-A602)
# ---------------------------------------------------------------------- #

def _make_admin_actor(deps: dict, name: str = "actor-admin"):
    """Legt einen Principal mit Rolle admin an (fuer principal.manage)."""
    admin_role = deps["roles"].get_by_name("admin")
    return deps["principals"].create(
        name=name,
        role_id=admin_role.row_id,
        kind=PrincipalKind.HUMAN,
        password_hash=None,
    )


def _make_role_without_device_read(deps: dict, name: str = "no_dev_read"):
    """Legt eine Rolle ohne device.read an (nur audit.read)."""
    conn = deps["principals"]._conn
    conn.execute(
        "INSERT INTO roles (name, description, created_at) "
        "VALUES (?, ?, ?)",
        (name, "Test-Rolle ohne device.read",
         "2026-09-27T00:00:00+00:00"),
    )
    conn.commit()
    deps["role_perms"].assign(name, "audit.read")
    return deps["roles"].get_by_name(name)


def test_create_principal_role_without_device_read(
    deps: dict, audit: AuditWriter,
) -> None:
    actor = _make_admin_actor(deps)
    _make_role_without_device_read(deps)
    svc = AccessService(
        deps["principals"], deps["roles"], deps["perms"],
        deps["role_perms"], deps["checker"], audit,
        session_repo=SessionRepository(
            deps["principals"]._conn
        ),
    )
    with pytest.raises(AccessServiceError) as exc_info:
        svc.create_principal(
            actor.name, name="neu1",
            role_name="no_dev_read",
        )
    assert "device.read" in str(exc_info.value)


def test_create_principal_role_with_device_read_ok(
    deps: dict, audit: AuditWriter,
) -> None:
    actor = _make_admin_actor(deps)
    svc = AccessService(
        deps["principals"], deps["roles"], deps["perms"],
        deps["role_perms"], deps["checker"], audit,
        session_repo=SessionRepository(
            deps["principals"]._conn
        ),
    )
    p = svc.create_principal(
        actor.name, name="neu2", role_name="viewer",
    )
    assert p.name == "neu2"
