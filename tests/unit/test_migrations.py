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
    SchemaVersionError,
    _parse_migration_version,
    apply_migrations,
    check_schema_version,
    connect,
    ensure_schema_migrations,
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


# ------------------------------------------------------------------ #
# 3.6.15a: Migrations-Tracking + Dateinamen-Parsing
# ------------------------------------------------------------------ #
# Diese Tests pruefen das neue Verhalten von apply_migrations
# (Versionen in schema_migrations eintragen, bereits angewandte
# Dateien ueberspringen) sowie die strikte vierstellige
# Dateinamen-Erkennung.
#
# Wichtig: NICHT die bestehende `conn`-Fixture verwenden --
# die ist bereits migriert und wuerde den Skip-Zustand
# verfaelschen. Alle Tests bauen ihre eigene tmp-DB.

_WM_SQL_A = "CREATE TABLE IF NOT EXISTS wm_a (id INTEGER PRIMARY KEY);"
_WM_SQL_B = "CREATE TABLE IF NOT EXISTS wm_b (id INTEGER PRIMARY KEY);"
_WM_SQL_C = "CREATE TABLE IF NOT EXISTS wm_c (id INTEGER PRIMARY KEY);"


def _write_migration(d: Path, name: str, sql: str) -> Path:
    f = d / name
    f.write_text(sql, encoding="utf-8")
    return f


def _versions_in_db(c: sqlite3.Connection) -> list[int]:
    rows = c.execute(
        "SELECT version FROM schema_migrations ORDER BY version"
    ).fetchall()
    return [int(r[0]) for r in rows]


def test_parse_version_vierstellig_normal():
    assert _parse_migration_version("0003_approvals.sql") == 3


def test_parse_version_null_erlaubt():
    # 0000 ist kein Sonderfall.
    assert _parse_migration_version("0000_init.sql") == 0


def test_parse_version_fuenfstellig_abgelehnt():
    # "10000_x.sql" darf NICHT als 1000 gelesen werden.
    assert _parse_migration_version("10000_x.sql") is None


def test_parse_version_kein_praefix():
    assert _parse_migration_version("init.sql") is None


def test_parse_version_drei_ziffern():
    assert _parse_migration_version("003_x.sql") is None


def test_apply_traegt_alle_versionen_ein(tmp_path):
    d = tmp_path / "migrations"
    d.mkdir()
    _write_migration(d, "0001_a.sql", _WM_SQL_A)
    _write_migration(d, "0002_b.sql", _WM_SQL_B)
    _write_migration(d, "0003_c.sql", _WM_SQL_C)

    c = connect(tmp_path / "wm1.db")
    applied = apply_migrations(c, d)

    assert applied == ["0001_a.sql", "0002_b.sql", "0003_c.sql"]
    assert _versions_in_db(c) == [1, 2, 3]
    c.close()


def test_apply_zweiter_lauf_skip(tmp_path, capsys):
    # Auflage 393: Skip-Verhalten explizit.
    d = tmp_path / "migrations"
    d.mkdir()
    _write_migration(d, "0001_a.sql", _WM_SQL_A)
    _write_migration(d, "0002_b.sql", _WM_SQL_B)

    c = connect(tmp_path / "wm2.db")
    first = apply_migrations(c, d)
    assert first == ["0001_a.sql", "0002_b.sql"]

    capsys.readouterr()  # ersten Lauf verwerfen
    second = apply_migrations(c, d)
    out = capsys.readouterr().out

    assert second == []
    # Auflage 394: kein stiller Skip.
    assert "uebersprungen (bereits angewandt): 0001_a.sql" in out
    assert "uebersprungen (bereits angewandt): 0002_b.sql" in out
    assert _versions_in_db(c) == [1, 2]
    c.close()


def test_apply_bestehende_zeile_2_bleibt(tmp_path):
    # Bestehende Version 2 (aus 0002_inventory.sql) bleibt stehen,
    # 0001 und 0003 werden nachgetragen. applied_at von Version 2
    # wird NICHT ueberschrieben (INSERT OR IGNORE).
    d = tmp_path / "migrations"
    d.mkdir()
    _write_migration(d, "0001_a.sql", _WM_SQL_A)
    _write_migration(d, "0002_b.sql", _WM_SQL_B)
    _write_migration(d, "0003_c.sql", _WM_SQL_C)

    c = connect(tmp_path / "wm3.db")
    ensure_schema_migrations(c)
    c.execute(
        "INSERT INTO schema_migrations (version, applied_at) "
        "VALUES (2, '2026-01-01T00:00:00.000Z')"
    )
    c.commit()

    applied = apply_migrations(c, d)

    assert applied == ["0001_a.sql", "0003_c.sql"]
    assert _versions_in_db(c) == [1, 2, 3]
    row = c.execute(
        "SELECT applied_at FROM schema_migrations WHERE version = 2"
    ).fetchone()
    assert row[0] == "2026-01-01T00:00:00.000Z"
    c.close()


def test_apply_datei_ohne_praefix_uebersprungen(tmp_path, capsys):
    d = tmp_path / "migrations"
    d.mkdir()
    _write_migration(d, "init.sql", _WM_SQL_A)
    _write_migration(d, "0001_a.sql", _WM_SQL_A)

    c = connect(tmp_path / "wm4.db")
    applied = apply_migrations(c, d)
    out = capsys.readouterr().out

    assert applied == ["0001_a.sql"]
    assert _versions_in_db(c) == [1]
    assert "kein vierstelliges Versionspraefix" in out
    assert "init.sql" in out
    c.close()


def test_apply_fuenfstellige_datei_uebersprungen(tmp_path, capsys):
    d = tmp_path / "migrations"
    d.mkdir()
    _write_migration(d, "10000_x.sql", _WM_SQL_A)
    _write_migration(d, "0001_a.sql", _WM_SQL_A)

    c = connect(tmp_path / "wm5.db")
    applied = apply_migrations(c, d)
    out = capsys.readouterr().out

    assert applied == ["0001_a.sql"]
    assert _versions_in_db(c) == [1]
    assert "kein vierstelliges Versionspraefix" in out
    assert "10000_x.sql" in out
    c.close()


def test_apply_nicht_sql_datei_ignoriert(tmp_path):
    d = tmp_path / "migrations"
    d.mkdir()
    _write_migration(d, "0001_a.sql", _WM_SQL_A)
    _write_migration(d, "0002_b.txt", _WM_SQL_B)
    (d / "notes.md").write_text("# nichts", encoding="utf-8")

    c = connect(tmp_path / "wm6.db")
    applied = apply_migrations(c, d)

    assert applied == ["0001_a.sql"]
    assert _versions_in_db(c) == [1]
    c.close()


def test_apply_fehlendes_verzeichnis_wirft(tmp_path):
    c = connect(tmp_path / "wm7.db")
    with pytest.raises(FileNotFoundError):
        apply_migrations(c, tmp_path / "gibt_es_nicht")
    c.close()


def test_apply_version_0_erlaubt(tmp_path):
    d = tmp_path / "migrations"
    d.mkdir()
    _write_migration(d, "0000_init.sql", _WM_SQL_A)

    c = connect(tmp_path / "wm8.db")
    applied = apply_migrations(c, d)

    assert applied == ["0000_init.sql"]
    assert _versions_in_db(c) == [0]
    c.close()


# ------------------------------------------------------------------ #
# 3.6.15a Fix D: check_schema_version
# ------------------------------------------------------------------ #
# Auflagen 403 (diagnostische Meldung), 404 (0==0 still),
# 405 (logger.warning statt print bei Downgrade).

def _prepare_db_with_version(c, version: int) -> None:
    ensure_schema_migrations(c)
    c.execute(
        "INSERT INTO schema_migrations (version, applied_at) "
        "VALUES (?, '2026-01-01T00:00:00.000Z')",
        (version,),
    )
    c.commit()


def test_check_schema_equal_still(tmp_path):
    # DB == Datei: kein raise, keine Warnung.
    d = tmp_path / "migrations"
    d.mkdir()
    _write_migration(d, "0001_a.sql", _WM_SQL_A)
    _write_migration(d, "0002_b.sql", _WM_SQL_B)

    c = connect(tmp_path / "cs1.db")
    _prepare_db_with_version(c, 2)
    check_schema_version(c, d)  # kein raise
    c.close()


def test_check_schema_db_kleiner_datei_wirft(tmp_path):
    # DB < Datei: SchemaVersionError.
    d = tmp_path / "migrations"
    d.mkdir()
    _write_migration(d, "0001_a.sql", _WM_SQL_A)
    _write_migration(d, "0002_b.sql", _WM_SQL_B)

    c = connect(tmp_path / "cs2.db")
    _prepare_db_with_version(c, 1)
    with pytest.raises(SchemaVersionError):
        check_schema_version(c, d)
    c.close()


def test_check_schema_db_groesser_datei_warnung(
    tmp_path, caplog,
):
    # DB > Datei: Warnung via logger.warning, kein raise.
    import logging as _logging
    d = tmp_path / "migrations"
    d.mkdir()
    _write_migration(d, "0001_a.sql", _WM_SQL_A)

    c = connect(tmp_path / "cs3.db")
    _prepare_db_with_version(c, 5)
    with caplog.at_level(
        _logging.WARNING,
        logger="core.inventory.repository",
    ):
        check_schema_version(c, d)  # kein raise
    assert any(
        "Downgrade" in rec.message for rec in caplog.records
    ), caplog.records
    c.close()


def test_check_schema_tabelle_fehlt(tmp_path):
    # Auflage 403: diagnostische Meldung.
    d = tmp_path / "migrations"
    d.mkdir()
    _write_migration(d, "0001_a.sql", _WM_SQL_A)

    c = connect(tmp_path / "cs4.db")
    # schema_migrations NICHT anlegen.
    with pytest.raises(
        SchemaVersionError, match="schema_migrations fehlt",
    ):
        check_schema_version(c, d)
    c.close()


def test_check_schema_leeres_verzeichnis_und_db_0(tmp_path):
    # Auflage 404: 0 == 0 -> still, kein raise.
    d = tmp_path / "migrations"
    d.mkdir()  # keine *.sql-Datei

    c = connect(tmp_path / "cs5.db")
    _prepare_db_with_version(c, 0)
    check_schema_version(c, d)  # kein raise
    c.close()
