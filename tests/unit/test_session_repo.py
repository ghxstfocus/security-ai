# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tests fuer core/access/session_repo.py.

Auflage 29: TemporaryDirectory + Datei-sqlite3.connect,
NICHT :memory:. Grund: apply_migrations liest
data/migrations/*.sql; :memory: verliert Schema bei
Connection-Wechsel.
"""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from core.access.models import PrincipalKind, to_utc
from core.access.repository import (
    PrincipalRepository,
    RoleRepository,
)
from core.access.session_repo import (
    LoginAttemptRepository,
    SessionRepository,
    SessionRepositoryError,
)
from tests.unit._helpers import migrated_conn

# ---------------------------------------------------------------------- #
# Fixtures
# ---------------------------------------------------------------------- #

@pytest.fixture()
def conn(tmp_path: Path) -> sqlite3.Connection:
    c = migrated_conn(tmp_path)
    roles = RoleRepository(c)
    viewer = roles.get_by_name("viewer")
    principals = PrincipalRepository(c)
    principals.create(
        name="alice",
        role_id=viewer.row_id,
        kind=PrincipalKind.HUMAN,
    )
    principals.create(
        name="bob",
        role_id=viewer.row_id,
        kind=PrincipalKind.HUMAN,
    )
    yield c
    c.close()


@pytest.fixture()
def repo(conn: sqlite3.Connection) -> SessionRepository:
    return SessionRepository(conn)


@pytest.fixture()
def attempts(conn: sqlite3.Connection) -> LoginAttemptRepository:
    return LoginAttemptRepository(conn)


def _now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------- #
# SessionRepository: create + get
# ---------------------------------------------------------------------- #

def test_create_and_get(repo: SessionRepository) -> None:
    s = repo.create("sid-1", "alice", ip="10.0.0.1",
                    user_agent="pytest")
    assert s.id == "sid-1"
    assert s.principal_name == "alice"
    assert s.ip == "10.0.0.1"
    assert s.user_agent == "pytest"
    assert s.revoked_at is None
    assert s.is_active is True
    got = repo.get("sid-1")
    assert got is not None
    assert got.id == "sid-1"


def test_get_unknown_returns_none(repo: SessionRepository) -> None:
    assert repo.get("does-not-exist") is None


def test_get_empty_string_returns_none(
    repo: SessionRepository,
) -> None:
    assert repo.get("") is None


def test_create_duplicate_raises(
    repo: SessionRepository,
) -> None:
    repo.create("sid-dup", "alice")
    with pytest.raises(SessionRepositoryError):
        repo.create("sid-dup", "alice")


def test_create_empty_session_id_raises(
    repo: SessionRepository,
) -> None:
    with pytest.raises(SessionRepositoryError):
        repo.create("", "alice")


def test_create_empty_principal_name_raises(
    repo: SessionRepository,
) -> None:
    with pytest.raises(SessionRepositoryError):
        repo.create("sid-x", "")


# ---------------------------------------------------------------------- #
# touch
# ---------------------------------------------------------------------- #

def test_touch_updates_last_seen(
    repo: SessionRepository,
) -> None:
    t0 = _now()
    s = repo.create("sid-t", "alice", now=t0)
    t1 = t0 + timedelta(seconds=10)
    ok = repo.touch("sid-t", now=t1)
    assert ok is True
    s2 = repo.get("sid-t")
    assert s2 is not None
    assert s2.last_seen_at > s.last_seen_at


def test_touch_unknown_returns_false(
    repo: SessionRepository,
) -> None:
    assert repo.touch("nope") is False


def test_touch_revoked_returns_false(
    repo: SessionRepository,
) -> None:
    repo.create("sid-r", "alice")
    assert repo.revoke("sid-r") is True
    assert repo.touch("sid-r") is False


def test_touch_updates_ip_user_agent(
    repo: SessionRepository,
) -> None:
    repo.create("sid-u", "alice", ip="10.0.0.1",
                user_agent="old")
    repo.touch("sid-u", ip="10.0.0.2", user_agent="new")
    s = repo.get("sid-u")
    assert s is not None
    assert s.ip == "10.0.0.2"
    assert s.user_agent == "new"


# ---------------------------------------------------------------------- #
# revoke
# ---------------------------------------------------------------------- #

def test_revoke_returns_true_then_false(
    repo: SessionRepository,
) -> None:
    repo.create("sid-v", "alice")
    assert repo.revoke("sid-v") is True
    assert repo.revoke("sid-v") is False


def test_revoke_unknown_returns_false(
    repo: SessionRepository,
) -> None:
    assert repo.revoke("nope") is False


def test_revoked_session_is_inactive(
    repo: SessionRepository,
) -> None:
    repo.create("sid-i", "alice")
    repo.revoke("sid-i")
    s = repo.get("sid-i")
    assert s is not None
    assert s.is_active is False
    assert s.revoked_at is not None


# ---------------------------------------------------------------------- #
# revoke_all_for_principal
# ---------------------------------------------------------------------- #

def test_revoke_all_for_principal(
    repo: SessionRepository,
) -> None:
    repo.create("sid-a1", "alice")
    repo.create("sid-a2", "alice")
    repo.create("sid-b1", "bob")
    n = repo.revoke_all_for_principal("alice")
    assert n == 2
    a1 = repo.get("sid-a1")
    a2 = repo.get("sid-a2")
    b1 = repo.get("sid-b1")
    assert a1 is not None and a1.revoked_at is not None
    assert a2 is not None and a2.revoked_at is not None
    assert b1 is not None and b1.revoked_at is None


def test_revoke_all_for_principal_empty_name(
    repo: SessionRepository,
) -> None:
    assert repo.revoke_all_for_principal("") == 0


# ---------------------------------------------------------------------- #
# purge_expired (Auflage 25)
# ---------------------------------------------------------------------- #

def test_purge_expired_keeps_fresh_revoked(
    repo: SessionRepository,
) -> None:
    t0 = _now()
    repo.create("sid-fresh", "alice", now=t0)
    repo.revoke("sid-fresh", now=t0)
    n = repo.purge_expired(before=t0 - timedelta(days=1))
    assert n == 0
    assert repo.get("sid-fresh") is not None


def test_purge_expired_deletes_old_revoked(
    repo: SessionRepository,
) -> None:
    t_old = _now() - timedelta(days=60)
    t_cut = _now() - timedelta(days=30)
    repo.create("sid-old", "alice", now=t_old)
    repo.revoke("sid-old", now=t_old)
    n = repo.purge_expired(before=t_cut)
    assert n == 1
    assert repo.get("sid-old") is None


def test_purge_expired_deletes_old_inactive(
    repo: SessionRepository,
) -> None:
    t_old = _now() - timedelta(days=60)
    t_cut = _now() - timedelta(days=30)
    repo.create("sid-stale", "alice", now=t_old)
    n = repo.purge_expired(before=t_cut)
    assert n == 1
    assert repo.get("sid-stale") is None


# ---------------------------------------------------------------------- #
# to_utc (Auflage 18)
# ---------------------------------------------------------------------- #

def test_to_utc_naive_datetime_raises() -> None:
    with pytest.raises(ValueError):
        to_utc(datetime(2026, 1, 1, 12, 0, 0))  # noqa: DTZ001 - absichtlich naiv (Negativtest)


def test_to_utc_iso_string_with_tz() -> None:
    dt = to_utc("2026-01-01T12:00:00+00:00")
    assert dt.tzinfo is not None


def test_to_utc_string_without_tz_raises() -> None:
    with pytest.raises(ValueError):
        to_utc("2026-01-01T12:00:00")


def test_to_utc_non_datetime_raises() -> None:
    # TypeError statt ValueError (A1429, TRY004-Fix):
    # falscher Typ -> TypeError (Python-Konvention).
    with pytest.raises(TypeError):
        to_utc(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------- #
# LoginAttemptRepository
# ---------------------------------------------------------------------- #

def test_attempt_record_and_count(
    attempts: LoginAttemptRepository,
) -> None:
    t0 = _now()
    attempts.record(ip="10.0.0.1", principal_name="alice",
                    success=False, now=t0)
    attempts.record(ip="10.0.0.1", principal_name="alice",
                    success=False, now=t0)
    attempts.record(ip="10.0.0.1", principal_name="alice",
                    success=True, now=t0)
    n = attempts.count_recent_failures("10.0.0.1", now=t0)
    assert n == 2


def test_attempt_count_ignores_other_ip(
    attempts: LoginAttemptRepository,
) -> None:
    t0 = _now()
    attempts.record(ip="10.0.0.1", success=False, now=t0)
    attempts.record(ip="10.0.0.2", success=False, now=t0)
    n = attempts.count_recent_failures("10.0.0.1", now=t0)
    assert n == 1


def test_attempt_count_respects_window(
    attempts: LoginAttemptRepository,
) -> None:
    t0 = _now()
    old = t0 - timedelta(hours=1)
    attempts.record(ip="10.0.0.1", success=False, now=old)
    attempts.record(ip="10.0.0.1", success=False, now=t0)
    n = attempts.count_recent_failures(
        "10.0.0.1", window_seconds=900, now=t0
    )
    assert n == 1


def test_attempt_record_empty_ip_raises(
    attempts: LoginAttemptRepository,
) -> None:
    with pytest.raises(SessionRepositoryError):
        attempts.record(ip="", success=False)


def test_attempt_count_empty_ip_returns_zero(
    attempts: LoginAttemptRepository,
) -> None:
    assert attempts.count_recent_failures("") == 0


def test_attempt_purge_older_than(
    attempts: LoginAttemptRepository,
) -> None:
    t_old = _now() - timedelta(days=60)
    attempts.record(ip="10.0.0.1", success=False, now=t_old)
    n = attempts.purge_older_than(days=30)
    assert n == 1
