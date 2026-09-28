"""
RateLimitService-Tests (Punkt 9, Auflage 665/666).

Prueft das SQLite-basierte Rate-Limit isoliert,
inklusive Multi-Worker-Sicherheit (zwei Instanzen
auf derselben DB).
"""
from __future__ import annotations

from datetime import UTC

from core.services.rate_limit_service import (
    RateLimitService,
    RateLimitServiceError,
)
from tests.unit._helpers import migrated_conn


def test_limit_and_retry_after(tmp_path):
    conn = migrated_conn(tmp_path)
    svc = RateLimitService(conn, window_seconds=60, max_requests=2)
    assert svc.allow("alice") == (True, 0)
    assert svc.allow("alice") == (True, 0)
    allowed, retry = svc.allow("alice")
    assert allowed is False
    assert retry >= 1
    conn.close()


def test_different_principals_share_no_budget(tmp_path):
    conn = migrated_conn(tmp_path)
    svc = RateLimitService(conn, window_seconds=60, max_requests=1)
    assert svc.allow("alice") == (True, 0)
    assert svc.allow("bob") == (True, 0)
    assert svc.allow("alice")[0] is False
    assert svc.allow("bob")[0] is False
    conn.close()


def test_two_instances_share_limit(tmp_path):
    # Zwei Instanzen auf derselben DB = zwei Worker.
    conn1 = migrated_conn(tmp_path)
    conn2 = migrated_conn(tmp_path)
    svc1 = RateLimitService(conn1, window_seconds=60, max_requests=2)
    svc2 = RateLimitService(conn2, window_seconds=60, max_requests=2)
    assert svc1.allow("alice") == (True, 0)
    assert svc2.allow("alice") == (True, 0)
    # Drittes Zugriffsversuch, egal welche Instanz.
    assert svc1.allow("alice")[0] is False
    assert svc2.allow("alice")[0] is False
    conn1.close()
    conn2.close()


def test_window_expires(tmp_path):
    conn = migrated_conn(tmp_path)
    # Fenster 0 nicht erlaubt, also 1 Sekunde.
    svc = RateLimitService(conn, window_seconds=1, max_requests=1)
    assert svc.allow("alice") == (True, 0)
    assert svc.allow("alice")[0] is False
    # hit_at kuenstlich altern.
    from datetime import datetime, timedelta, timezone
    old = (
        datetime.now(UTC) - timedelta(seconds=5)
    ).isoformat()
    conn.execute("UPDATE chat_rate_hits SET hit_at = ?", (old,))
    conn.commit()
    assert svc.allow("alice") == (True, 0)
    conn.close()


def test_empty_principal_raises(tmp_path):
    conn = migrated_conn(tmp_path)
    svc = RateLimitService(conn)
    for bad in ("", None, 123):
        try:
            svc.allow(bad)  # type: ignore[arg-type]
            assert False, f"kein Fehler fuer {bad!r}"
        except RateLimitServiceError:
            pass
    conn.close()


def test_none_conn_raises():
    try:
        RateLimitService(None)  # type: ignore[arg-type]
        assert False, "kein Fehler fuer conn=None"
    except RateLimitServiceError:
        pass


def test_household_deletes_old_rows(tmp_path):
    conn = migrated_conn(tmp_path)
    svc = RateLimitService(conn, window_seconds=60, max_requests=5)
    # Alte Zeile direkt einsetzen.
    from datetime import datetime, timedelta, timezone
    old = (
        datetime.now(UTC) - timedelta(seconds=300)
    ).isoformat()
    conn.execute(
        "INSERT INTO chat_rate_hits (principal_name, hit_at) "
        "VALUES (?, ?)",
        ("alice", old),
    )
    conn.commit()
    # allow() raeumt auf.
    assert svc.allow("alice") == (True, 0)
    n = conn.execute(
        "SELECT COUNT(*) FROM chat_rate_hits "
        "WHERE hit_at < ?",
        (
            (datetime.now(UTC) - timedelta(seconds=60))
            .isoformat(),
        ),
    ).fetchone()[0]
    assert n == 0
    conn.close()
