"""
Tests fuer build_chat_context since_hours (Punkt 31, A847/A852).
"""
from __future__ import annotations

from pathlib import Path

from core.context.builder import build_chat_context
from tests.unit._helpers import migrated_conn


def test_dict_enthaelt_since_hours(tmp_path: Path):
    conn = migrated_conn(tmp_path)
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    ctx = build_chat_context(conn, audit_dir, since_hours=48)
    assert ctx["since_hours"] == 48


def test_dict_default_since_hours_24(tmp_path: Path):
    conn = migrated_conn(tmp_path)
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    ctx = build_chat_context(conn, audit_dir)
    assert ctx["since_hours"] == 24
