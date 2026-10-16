"""Tests fuer die Guardrail-Permissions (Phase 5, U6).

Prueft die Rollen-Zuordnungen aus
data/migrations/0017_guardrail_permissions.sql (admin)
und data/migrations/0018_guardrail_permissions.sql
(operator, viewer).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

_MIGRATIONS_DIR = (
    Path(__file__).resolve().parents[2] / "data" / "migrations"
)
_MIG_0005 = _MIGRATIONS_DIR / "0005_principals.sql"
_MIG_0017 = _MIGRATIONS_DIR / "0017_guardrail_permissions.sql"
_MIG_0018 = _MIGRATIONS_DIR / "0018_guardrail_permissions.sql"


def _has_permission(
    db_path: Path, role_name: str, permission_code: str
) -> bool:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute(
            "SELECT 1 FROM role_permissions rp "
            "JOIN roles r ON r.id = rp.role_id "
            "JOIN permissions p ON p.id = rp.permission_id "
            "WHERE r.name = ? AND p.code = ?",
            (role_name, permission_code),
        )
        return cur.fetchone() is not None
    finally:
        conn.close()


@pytest.fixture
def _db_path(tmp_path: Path) -> Path:
    db_path = tmp_path / "guardrails.db"
    for mig in (_MIG_0005, _MIG_0017, _MIG_0018):
        assert mig.exists(), f"Migration fehlt: {mig}"
        sql = mig.read_text(encoding="utf-8")
        conn = sqlite3.connect(db_path)
        conn.executescript(sql)
        conn.commit()
        conn.close()
    yield db_path


def test_admin_has_guardrail_manage(_db_path: Path) -> None:
    assert _has_permission(_db_path, "admin", "guardrail.manage")


def test_admin_has_guardrail_view(_db_path: Path) -> None:
    assert _has_permission(_db_path, "admin", "guardrail.view")


def test_operator_has_guardrail_view(_db_path: Path) -> None:
    assert _has_permission(_db_path, "operator", "guardrail.view")


def test_operator_does_not_have_guardrail_manage(
    _db_path: Path,
) -> None:
    assert not _has_permission(
        _db_path, "operator", "guardrail.manage"
    )


def test_viewer_has_guardrail_view(_db_path: Path) -> None:
    assert _has_permission(_db_path, "viewer", "guardrail.view")


def test_viewer_does_not_have_guardrail_manage(
    _db_path: Path,
) -> None:
    assert not _has_permission(
        _db_path, "viewer", "guardrail.manage"
    )