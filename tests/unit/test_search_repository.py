"""
SearchRepository-Tests (3.6.16, Auflage 559).

tmp-SQLite, je ein Eintrag pro Tabelle, Suche mit
Treffer, kein Treffer, LIKE-Sonderzeichen, Limit.
"""
from __future__ import annotations

from core.search.repository import SearchRepository, escape_like
from tests.unit._helpers import migrated_conn


def _seed(conn):
    conn.execute(
        "INSERT INTO devices (identifier, entity_name, "
        "network_type, first_seen, last_seen) "
        "VALUES (?, ?, ?, ?, ?)",
        ("192.168.178.42", "kamera", "Hauptnetz",
         "2026-09-26T10:00:00+00:00", "2026-09-26T10:00:00+00:00"),
    )
    conn.execute(
        "INSERT INTO whitelisted_devices (timestamp, identifier, "
        "entity_name) VALUES (?, ?, ?)",
        ("2026-09-26T10:00:00+00:00", "192.168.178.42", "kamera"),
    )
    conn.execute(
        "INSERT INTO change_requests (change_id, timestamp, title, "
        "description, requested_by, status, type, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("CHG-2026-00001", "2026-09-26T10:00:00+00:00",
         "Kamera-Block", "block", "admin-web", "draft",
         "config_change", "2026-09-26T10:00:00+00:00"),
    )
    conn.execute(
        "INSERT INTO approvals (request_id, timestamp, tool_name, "
        "args_json, requested_by, status, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("APR-2026-00001", "2026-09-26T10:00:00+00:00",
         "nmap_scan", "[]", "admin-web", "pending",
         "2026-09-26T10:00:00+00:00"),
    )
    conn.commit()


class TestSearchRepository:
    def test_search_devices_hit(self, tmp_path):
        conn = migrated_conn(tmp_path)
        _seed(conn)
        repo = SearchRepository(conn)
        rows = repo.search_devices("kamera")
        assert len(rows) == 1
        assert rows[0]["identifier"] == "192.168.178.42"
        conn.close()

    def test_search_devices_no_hit(self, tmp_path):
        conn = migrated_conn(tmp_path)
        _seed(conn)
        repo = SearchRepository(conn)
        assert repo.search_devices("gibtsnicht") == []
        conn.close()

    def test_like_wildcard_escaped(self, tmp_path):
        conn = migrated_conn(tmp_path)
        _seed(conn)
        repo = SearchRepository(conn)
        # % darf nicht als Wildcard wirken.
        assert repo.search_devices("%") == []
        assert repo.search_devices("_") == []
        conn.close()

    def test_search_changes(self, tmp_path):
        conn = migrated_conn(tmp_path)
        _seed(conn)
        repo = SearchRepository(conn)
        rows = repo.search_changes("CHG-2026")
        assert len(rows) == 1
        assert rows[0]["change_id"] == "CHG-2026-00001"
        conn.close()

    def test_search_approvals(self, tmp_path):
        conn = migrated_conn(tmp_path)
        _seed(conn)
        repo = SearchRepository(conn)
        rows = repo.search_approvals("nmap")
        assert len(rows) == 1
        conn.close()

    def test_limit_enforced(self, tmp_path):
        conn = migrated_conn(tmp_path)
        for i in range(25):
            conn.execute(
                "INSERT INTO devices (identifier, entity_name, "
                "network_type, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?)",
                (f"host-{i:03d}", "host", "Hauptnetz",
                 "2026-09-26T10:00:00+00:00",
                 "2026-09-26T10:00:00+00:00"),
            )
        conn.commit()
        repo = SearchRepository(conn)
        rows = repo.search_devices("host", limit=20)
        assert len(rows) == 20
        conn.close()

    def test_escape_like_ordre(self):
        assert escape_like("a%b_c\\d") == "a\\%b\\_c\\\\d"

class TestSearchRepositoryRawConnection:
    """3.6.17: SearchRepository setzt row_factory defensiv."""

    def test_search_repository_with_raw_connection(self):
        import sqlite3 as _sq
        # Rohe Verbindung ohne row_factory.
        conn = _sq.connect(":memory:")
        assert conn.row_factory is None
        conn.execute(
            "CREATE TABLE devices ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "identifier TEXT NOT NULL UNIQUE, "
            "entity_name TEXT, "
            "network_type TEXT, "
            "first_seen TEXT NOT NULL, "
            "last_seen TEXT NOT NULL, "
            "notes TEXT)"
        )
        conn.execute(
            "INSERT INTO devices (identifier, entity_name, "
            "network_type, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            ("192.168.178.99", "kamera-raw", "Hauptnetz",
             "2026-09-27T10:00:00+00:00",
             "2026-09-27T10:00:00+00:00"),
        )
        conn.commit()
        repo = SearchRepository(conn)
        rows = repo.search_devices("kamera", 20)
        assert isinstance(rows, list)
        assert len(rows) == 1
        assert isinstance(rows[0], dict)
        assert rows[0]["identifier"] == "192.168.178.99"
        conn.close()
