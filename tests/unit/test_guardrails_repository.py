"""Tests fuer core/guardrails/repository.py (Phase 5)."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from core.guardrails.models import GuardrailState
from core.guardrails.repository import (
    GuardrailNotFoundError,
    GuardrailRepository,
)

_MIG = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "migrations"
    / "0016_guardrails.sql"
)


def _insert_guardrail(
    db_path: Path,
    id_: str = "g1",
    name: str = "test",
    level: str = "info",
    state: str = "enabled",
) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO guardrails "
        "(id, name, level, state, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            id_,
            name,
            level,
            state,
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00:00+00:00",
        ),
    )
    conn.commit()
    conn.close()


@pytest.fixture
def _db_path(tmp_path: Path) -> Path:
    db_path = tmp_path / "guardrails.db"
    assert _MIG.exists(), f"Migration fehlt: {_MIG}"
    sql = _MIG.read_text(encoding="utf-8")
    conn = sqlite3.connect(db_path)
    conn.executescript(sql)
    conn.commit()
    conn.close()
    _insert_guardrail(db_path, "g1", "test", "info", "enabled")
    yield db_path


def test_migration_has_exactly_six_columns(_db_path: Path) -> None:
    conn = sqlite3.connect(_db_path)
    try:
        cur = conn.execute("PRAGMA table_info(guardrails)")
        rows = cur.fetchall()
    finally:
        conn.close()
    names = [row[1] for row in rows]
    assert names == [
        "id",
        "name",
        "level",
        "state",
        "created_at",
        "updated_at",
    ]


def test_set_state_updates_updated_at(_db_path: Path) -> None:
    conn = sqlite3.connect(_db_path)
    try:
        cur = conn.execute(
            "SELECT updated_at FROM guardrails WHERE id = ?", ("g1",)
        )
        updated_at_vor = cur.fetchone()[0]
    finally:
        conn.close()

    time.sleep(0.01)

    repo = GuardrailRepository(_db_path)
    repo.set_state("g1", "disabled")

    conn = sqlite3.connect(_db_path)
    try:
        cur = conn.execute(
            "SELECT updated_at FROM guardrails WHERE id = ?", ("g1",)
        )
        updated_at_nach = cur.fetchone()[0]
    finally:
        conn.close()

    assert updated_at_nach > updated_at_vor
    assert "+" in updated_at_nach or updated_at_nach.endswith("Z")

    g = repo.get("g1")
    assert g.state == GuardrailState.DISABLED
    assert isinstance(g.state, GuardrailState)


def test_get_unknown_id_raises(_db_path: Path) -> None:
    repo = GuardrailRepository(_db_path)
    with pytest.raises(GuardrailNotFoundError):
        repo.get("nicht-vorhanden")


def test_set_state_unknown_id_raises(_db_path: Path) -> None:
    repo = GuardrailRepository(_db_path)
    with pytest.raises(GuardrailNotFoundError):
        repo.set_state("nicht-vorhanden", "disabled")


def test_no_create_table_in_test_file() -> None:
    src = Path(__file__).read_text(encoding="utf-8")
    assert "CREATE TABLE" not in src