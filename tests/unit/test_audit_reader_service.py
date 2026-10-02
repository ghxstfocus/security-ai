"""
Tests fuer core/services/audit_reader_service.py.

Kategorie 3 (RBAC audit.read, Input-Validierung).
"""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from core.access.checker import (
    AccessChecker,
    AccessDeniedError,
)
from core.access.models import PrincipalKind
from core.access.repository import (
    PermissionRepository,
    PrincipalRepository,
    RoleRepository,
)
from core.services.audit_reader_service import (
    AuditReaderService,
    AuditReaderServiceError,
)
from harness.audit.writer import AuditWriter
from tests.unit._helpers import migrated_conn


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
    today = datetime.now(UTC).strftime("%Y-%m-%d")
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


# ---------------------------------------------------------------------- #
# Tests 3.6.8: list_recent_assessments
# ---------------------------------------------------------------------- #

def _create_principal(conn, name, role_name):
    roles = RoleRepository(conn)
    principals = PrincipalRepository(conn)
    role = roles.get_by_name(role_name)
    principals.create(
        name=name, role_id=role.row_id,
        kind=PrincipalKind.HUMAN,
    )


def test_list_recent_assessments_requires_alert_view(
    conn, tmp_path, monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    _create_principal(conn, "viewer1", "viewer")
    svc = AuditReaderService(
        AuditWriter(base_dir=tmp_path / "audit"),
        checker=AccessChecker.from_conn(conn),
    )
    with pytest.raises(AccessDeniedError):
        svc.list_recent_assessments("viewer1")


def test_list_recent_assessments_admin_ok(
    conn, tmp_path, monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    _create_principal(conn, "admin1", "admin")
    svc = AuditReaderService(
        AuditWriter(base_dir=tmp_path / "audit"),
        checker=AccessChecker.from_conn(conn),
    )
    out = svc.list_recent_assessments("admin1")
    assert out == []


def test_list_recent_assessments_operator_ok(
    conn, tmp_path, monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    _create_principal(conn, "op1", "operator")
    svc = AuditReaderService(
        AuditWriter(base_dir=tmp_path / "audit"),
        checker=AccessChecker.from_conn(conn),
    )
    out = svc.list_recent_assessments("op1")
    assert out == []


def test_list_recent_assessments_limit_low(
    conn, tmp_path, monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    _create_principal(conn, "admin1", "admin")
    svc = AuditReaderService(
        AuditWriter(base_dir=tmp_path / "audit"),
        checker=AccessChecker.from_conn(conn),
    )
    with pytest.raises(AuditReaderServiceError):
        svc.list_recent_assessments("admin1", limit=0)


def test_list_recent_assessments_limit_high(
    conn, tmp_path, monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    _create_principal(conn, "admin1", "admin")
    svc = AuditReaderService(
        AuditWriter(base_dir=tmp_path / "audit"),
        checker=AccessChecker.from_conn(conn),
    )
    with pytest.raises(AuditReaderServiceError):
        svc.list_recent_assessments("admin1", limit=1001)


def test_list_recent_assessments_limit_not_int(
    conn, tmp_path, monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    _create_principal(conn, "admin1", "admin")
    svc = AuditReaderService(
        AuditWriter(base_dir=tmp_path / "audit"),
        checker=AccessChecker.from_conn(conn),
    )
    with pytest.raises(AuditReaderServiceError):
        svc.list_recent_assessments("admin1", limit="100")


def test_list_recent_assessments_limit_bool(
    conn, tmp_path, monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    _create_principal(conn, "admin1", "admin")
    svc = AuditReaderService(
        AuditWriter(base_dir=tmp_path / "audit"),
        checker=AccessChecker.from_conn(conn),
    )
    with pytest.raises(AuditReaderServiceError):
        svc.list_recent_assessments("admin1", limit=True)


def test_list_recent_assessments_rbac_before_limit(
    conn, tmp_path, monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    _create_principal(conn, "viewer1", "viewer")
    svc = AuditReaderService(
        AuditWriter(base_dir=tmp_path / "audit"),
        checker=AccessChecker.from_conn(conn),
    )
    with pytest.raises(AccessDeniedError):
        svc.list_recent_assessments("viewer1", limit=0)


# ---------------------------------------------------------------------- #
# 3.6.8b Regression (Auflage 32)
# ---------------------------------------------------------------------- #

def test_list_recent_assessments_reads_from_configured_base_dir(
    conn, tmp_path, monkeypatch,
):
    """
    Regression: list_recent_assessments muss die base_dir des
    AuditWriter nutzen, nicht den CWD-Default.

    Test: CWD auf ein leeres tmp wechseln (kein audit-logs/),
    base_dir = tmp/audit mit einer Zeile. Ohne den Fix waere
    das Ergebnis leer (CWD hätte nichts), mit dem Fix sichtbar.
    """
    _create_principal(conn, "admin1", "admin")

    # CWD auf ein leeres Verzeichnis umlenken: dort liegt kein
    # audit-logs/, damit der Default-Pfad leer bliebe.
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)

    audit_dir = tmp_path / "audit"
    writer = AuditWriter(base_dir=audit_dir)
    writer.log(
        agent="security_ai",
        tool="risk.unknown_device",
        policy_result="ALLOWED",
        permission_level=0,
        execution_status="OK",
        details={
            "kind": "risk_assessment",
            "event_id": "EVT-2026-09-22-cafebabe",
            "category": "CONFIRMED",
            "score": 0.9,
            "rule_id": "unknown_device",
            "base": 0.5,
            "modifiers": [],
            "reasons": [],
        },
    )

    svc = AuditReaderService(
        audit_writer=writer,
        checker=AccessChecker.from_conn(conn),
    )
    out = svc.list_recent_assessments("admin1")
    assert len(out) == 1, (
        "Service liest nicht aus der konfigurierten base_dir "
        f"(bekam {len(out)} Eintraege)"
    )
    assert out[0]["event_id"] == "EVT-2026-09-22-cafebabe"


# ------------------------------------------------------------------ #
# list_recent_by_kinds (T4, Auflage 1711)
# ------------------------------------------------------------------ #

def test_list_recent_by_kinds_filters_kinds(
    conn, audit: AuditWriter, svc: AuditReaderService,
) -> None:
    _create_principal(conn, "admin1", "admin")
    audit.log(
        agent="security_ai", tool="test",
        policy_result="ALLOWED", permission_level=0,
        execution_status="OK",
        details={"kind": "change_created"},
    )
    audit.log(
        agent="security_ai", tool="test",
        policy_result="ALLOWED", permission_level=0,
        execution_status="OK",
        details={"kind": "tool_call"},
    )
    audit.log(
        agent="security_ai", tool="test",
        policy_result="ALLOWED", permission_level=0,
        execution_status="OK",
        details={"kind": "approval_requested"},
    )
    out = svc.list_recent_by_kinds(
        "admin1", {"change_created", "approval_requested"},
    )
    kinds = {e["kind"] for e in out}
    assert kinds == {"change_created", "approval_requested"}


def test_list_recent_by_kinds_limit(
    conn, audit: AuditWriter, svc: AuditReaderService,
) -> None:
    _create_principal(conn, "admin1", "admin")
    for _ in range(5):
        audit.log(
            agent="security_ai", tool="test",
            policy_result="ALLOWED", permission_level=0,
            execution_status="OK",
            details={"kind": "change_created"},
        )
    out = svc.list_recent_by_kinds(
        "admin1", {"change_created"}, limit=3,
    )
    assert len(out) == 3


# --- Punkt 79: list_recent_assessments_with_context ---

def test_list_with_context_uses_trigger_event_id():
    """Die Methode existiert auf dem Service."""
    from core.services.audit_reader_service import (
        AuditReaderService,
    )
    assert hasattr(
        AuditReaderService,
        "list_recent_assessments_with_context",
    )


def test_list_with_context_fallback_to_event_id():
    """Ohne trigger_event_id wird event_id genutzt."""
    entry = {"event_id": "EVT-X", "trigger_event_id": None}
    lookup = entry.get("trigger_event_id") or entry.get("event_id")
    assert lookup == "EVT-X"


def test_list_with_context_no_trigger_no_error():
    """Ohne beide IDs: kein Fehler."""
    entry = {"event_id": None, "trigger_event_id": None}
    lookup = entry.get("trigger_event_id") or entry.get("event_id")
    assert lookup is None
