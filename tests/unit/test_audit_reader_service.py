"""
Tests fuer core/services/audit_reader_service.py.

Kategorie 3 (RBAC audit.read, Input-Validierung).
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.access.checker import AccessChecker
from core.access.repository import (
    PermissionRepository,
    PrincipalRepository,
    RoleRepository,
)
from core.services.audit_reader_service import (
    AuditReaderServiceError,
    AuditReaderService,
)
from tests.unit._helpers import migrated_conn
from harness.audit.writer import AuditWriter


@pytest.fixture()
def conn(tmp_path: Path) -> sqlite3.Connection:
    c = migrated_conn(tmp_path)
    yield c
    c.close()


@pytest.fixture()
def checker(conn: sqlite3.Connection) -> AccessChecker:
    principals = PrincipalRepository(conn)
    roles = RoleRepository(conn)
    perms = PermissionRepository(conn)
    viewer = roles.get_by_name("viewer")
    principals.create(name="alice", role_id=viewer.row_id)
    return AccessChecker(principals, roles, perms)


@pytest.fixture()
def audit(tmp_path: Path) -> AuditWriter:
    return AuditWriter(base_dir=tmp_path / "audit")


@pytest.fixture()
def svc(audit: AuditWriter, checker: AccessChecker) -> AuditReaderService:
    return AuditReaderService(audit_writer=audit, checker=checker)


# ---------------------------------------------------------------------- #
# Tests
# ---------------------------------------------------------------------- #

def test_read_day_no_permission(svc: AuditReaderService) -> None:
    with pytest.raises(Exception) as exc:
        svc.read_day("nichtda", "2026-09-22")
    assert "audit.read" in str(exc.value)


def test_read_day_ok(
    svc: AuditReaderService, audit: AuditWriter,
) -> None:
    audit.log(
        agent="security_ai", tool="test",
        policy_result="ALLOWED", permission_level=0,
        execution_status="OK",
    )
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    entries = svc.read_day("alice", today)
    assert len(entries) == 1
    assert entries[0]["agent"] == "security_ai"


def test_read_day_invalid_date(svc: AuditReaderService) -> None:
    # Auflage 51: drei Varianten
    for bad in ("2026-13-01", "2026-02-30", "2026-2-30"):
        with pytest.raises(AuditReaderServiceError):
            svc.read_day("alice", bad)


def test_read_day_traversal_blocked(svc: AuditReaderService) -> None:
    # Auflage 48: fuenf Varianten
    for bad in (
        "../../etc/passwd",
        "2026-09-22/../x",
        "2026-09-22\x00",
        "2026-9-22",
        "2026-02-30",
    ):
        with pytest.raises(AuditReaderServiceError):
            svc.read_day("alice", bad)


def test_read_day_missing_file_returns_empty(
    svc: AuditReaderService,
) -> None:
    # Datum in der Zukunft, keine Datei da
    assert svc.read_day("alice", "2099-01-01") == []


def test_read_all_sorts_descending(
    svc: AuditReaderService, audit: AuditWriter,
) -> None:
    audit.log(
        agent="security_ai", tool="a",
        policy_result="ALLOWED", permission_level=0,
        execution_status="OK",
    )
    audit.log(
        agent="security_ai", tool="b",
        policy_result="ALLOWED", permission_level=0,
        execution_status="OK",
    )
    entries = svc.read_all("alice")
    assert len(entries) == 2
    ts = [e["timestamp"] for e in entries]
    assert ts == sorted(ts, reverse=True)


def test_find_by_audit_id(
    svc: AuditReaderService, audit: AuditWriter,
) -> None:
    e = audit.log(
        agent="security_ai", tool="x",
        policy_result="ALLOWED", permission_level=0,
        execution_status="OK",
    )
    found = svc.find_by_audit_id("alice", e.audit_id)
    assert found is not None
    assert found["audit_id"] == e.audit_id
    # Unbekannte, aber gueltige audit_id
    assert svc.find_by_audit_id(
        "alice", "AUD-2099-01-01-00000000"
    ) is None
    # Ungueltiges Format
    with pytest.raises(AuditReaderServiceError):
        svc.find_by_audit_id("alice", "kaputt")


# ---------------------------------------------------------------------- #
# Test 3.6.8: ServiceError-Hierarchie
# ---------------------------------------------------------------------- #

def test_audit_reader_service_error_is_service_error():
    from core.services import ServiceError
    assert issubclass(AuditReaderServiceError, ServiceError)
