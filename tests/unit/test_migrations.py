"""
Tests fuer Migrationen.

Auflagen 1, 2, 3, 4, 6, 7.
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from core.access.repository import RoleRepository
from core.inventory.repository import (
    DEFAULT_MIGRATIONS_DIR,
    apply_migrations,
    connect,
)
from tests.unit._helpers import migrated_conn


PERMISSION_PATTERN = re.compile(
    r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$",
)


@pytest.fixture()
def conn(tmp_path: Path) -> sqlite3.Connection:
    c = migrated_conn(tmp_path)
    yield c
    c.close()


def test_alert_view_permission_exists(conn):
    row = conn.execute(
        "SELECT code, description FROM permissions "
        "WHERE code = 'alert.view'",
    ).fetchone()
    assert row is not None
    assert row[0] == "alert.view"


def test_alert_view_admin_has(conn):
    roles = RoleRepository(conn)
    admin = roles.get_by_name("admin")
    assert "alert.view" in admin.permissions
    assert admin.permissions.count("alert.view") == 1


def test_alert_view_operator_has(conn):
    roles = RoleRepository(conn)
    op = roles.get_by_name("operator")
    assert "alert.view" in op.permissions
    assert op.permissions.count("alert.view") == 1


def test_alert_view_viewer_not(conn):
    roles = RoleRepository(conn)
    viewer = roles.get_by_name("viewer")
    assert "alert.view" not in viewer.permissions
    assert isinstance(viewer.permissions, tuple)
    assert "*" not in viewer.permissions
    assert "all" not in viewer.permissions


def test_alert_view_system_not(conn):
    roles = RoleRepository(conn)
    system = roles.get_by_name("system")
    assert "alert.view" not in system.permissions
    assert isinstance(system.permissions, tuple)
    assert "*" not in system.permissions
    assert "all" not in system.permissions


def test_migrations_idempotent(conn):
    # Testet Idempotenz auf apply_migrations-Ebene.
    # Wenn apply_migrations ein Tracking hat, laeuft
    # 0007 beim zweiten Aufruf nicht. Fuer SQL-Level-
    # Idempotenz siehe test_migration_0007_sql_idempotent.
    before = conn.execute(
        "SELECT COUNT(*) FROM permissions "
        "WHERE code = 'alert.view'",
    ).fetchone()[0]
    before_rp = conn.execute(
        "SELECT COUNT(*) FROM role_permissions rp "
        "JOIN permissions p ON p.id = rp.permission_id "
        "WHERE p.code = 'alert.view'",
    ).fetchone()[0]
    apply_migrations(conn, DEFAULT_MIGRATIONS_DIR)
    after = conn.execute(
        "SELECT COUNT(*) FROM permissions "
        "WHERE code = 'alert.view'",
    ).fetchone()[0]
    after_rp = conn.execute(
        "SELECT COUNT(*) FROM role_permissions rp "
        "JOIN permissions p ON p.id = rp.permission_id "
        "WHERE p.code = 'alert.view'",
    ).fetchone()[0]
    assert before == after == 1
    assert before_rp == after_rp == 2


def test_migration_0007_sql_idempotent(tmp_path):
    # apply_migrations einmal (fuehrt 0007 aus),
    # dann 0007-SQL zweimal direkt.
    # Testet SQL-Level-Idempotenz.
    db = tmp_path / "t2.db"
    c = connect(db)
    apply_migrations(c, DEFAULT_MIGRATIONS_DIR)
    sql = (
        Path(DEFAULT_MIGRATIONS_DIR)
        / "0007_alert_permission.sql"
    ).read_text(encoding="utf-8")
    c.executescript(sql)
    c.executescript(sql)
    n = c.execute(
        "SELECT COUNT(*) FROM permissions "
        "WHERE code = 'alert.view'",
    ).fetchone()[0]
    assert n == 1
    m = c.execute(
        "SELECT COUNT(*) FROM role_permissions rp "
        "JOIN permissions p ON p.id = rp.permission_id "
        "WHERE p.code = 'alert.view'",
    ).fetchone()[0]
    assert m == 2
    c.close()


def test_no_wildcard_permissions(conn):
    rows = conn.execute(
        "SELECT code FROM permissions",
    ).fetchall()
    codes = [r[0] for r in rows]
    assert all("*" not in c for c in codes)
    assert all("?" not in c for c in codes)
    assert all(PERMISSION_PATTERN.match(c) for c in codes)
