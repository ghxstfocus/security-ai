"""
Tests fuer core/context/builder.py (Punkt 28, Auflage 726).
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from core.context.builder import build_chat_context
from core.inventory.repository import connect
from tests.unit._helpers import migrated_conn


def _seed_device(conn):
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO devices (identifier, entity_name, network_type, "
        "first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
        ("192.168.178.70", "test-device", "Hauptnetz", now, now),
    )
    conn.commit()


def _seed_approval(conn):
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO approvals (request_id, timestamp, tool_name, "
        "args_json, requested_by, status, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("APR-2099-00001", now, "nmap_scan", "[]", "admin-web",
         "pending", now),
    )
    conn.commit()


def _seed_change(conn):
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO change_requests (change_id, timestamp, title, "
        "description, requested_by, status, type, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("CHG-2099-00001", now, "Test-Change", "d", "admin-web",
         "pending_review", "config_change", now),
    )
    conn.commit()


def test_builder_returns_all_keys(tmp_path):
    conn = migrated_conn(tmp_path)
    audit = tmp_path / "audit"
    audit.mkdir()
    result = build_chat_context(conn, audit)
    for key in (
        "risk_assessments",
        "inventory_snapshot",
        "open_approvals",
        "open_changes",
        "log_excerpts",
        "recent_events",
    ):
        assert key in result, f"{key} fehlt"
    assert result["log_excerpts"] == ()
    assert result["recent_events"] == ()
    conn.close()


def test_builder_fills_db_sources(tmp_path):
    conn = migrated_conn(tmp_path)
    _seed_device(conn)
    _seed_approval(conn)
    _seed_change(conn)
    audit = tmp_path / "audit"
    audit.mkdir()
    result = build_chat_context(conn, audit)
    assert len(result["open_approvals"]) == 1
    assert len(result["open_changes"]) == 1
    # inventory_snapshot ist ein dict (aggregiert).
    assert isinstance(result["inventory_snapshot"], dict)
    conn.close()


def test_builder_empty_db_still_returns_keys(tmp_path):
    conn = migrated_conn(tmp_path)
    audit = tmp_path / "audit"
    audit.mkdir()
    result = build_chat_context(conn, audit)
    assert result["open_approvals"] == ()
    assert result["open_changes"] == ()
    assert result["risk_assessments"] == ()
    conn.close()
