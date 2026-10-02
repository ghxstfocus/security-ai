# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
SearchRepository: SQL-Suche fuer das Dashboard.

Kategorie 3 (3.6.16, Auflagen 553-556, Option D).

Design:
- Eigene Repo-Schicht fuer die querschnittliche Suche.
- Keine bestehenden Repos werden angefasst.
- Tabellen- und Feldnamen sind hart kodiert
  (Auflage 555). Keine dynamischen Namen aus User-Input.
- LIKE '%q%' mit LOWER(feld) LIKE LOWER(?)
  und ESCAPE '\\' (Auflage 527/528).
- Limit ist immer gesetzt, Default 20 (Auflage 556).
- Kein SELECT *. Explizite Feldlisten (Auflage 554).
- Rueckgabe pro Methode: Liste von dicts mit genau den
  Feldern, die der Link-Builder braucht.

Nicht hier:
- risk_assessments (JSONL, kein SQL). Der Filter liegt im
  SearchService (Auflage 557).
"""
from __future__ import annotations

import sqlite3
from typing import Any

DEFAULT_LIMIT = 20

# LIKE-Sonderzeichen escapen (Auflage 528).
# Reihenfolge: Backslash zuerst, sonst wird das
# Escape-Zeichen selbst noch einmal escaped.
def escape_like(q: str) -> str:
    return (
        q.replace("\\", "\\\\")
         .replace("%", "\\%")
         .replace("_", "\\_")
    )


def _pattern(q: str) -> str:
    return f"%{escape_like(q)}%"


class SearchRepository:
    """Suche in den durchsuchbaren SQL-Tabellen."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        if conn is None:
            raise ValueError("conn ist Pflicht")
        # 3.6.17: row_factory defensiv setzen, konsistent
        # zu ChangeRepository/ApprovalRepository.
        if conn.row_factory is None:
            conn.row_factory = sqlite3.Row
        self._conn = conn

    def _rows_to_dicts(
        self, cur: sqlite3.Cursor,
    ) -> list[dict[str, Any]]:
        cols = [d[0] for d in cur.description]
        out: list[dict[str, Any]] = []
        for row in cur.fetchall():
            out.append({c: row[c] for c in cols})
        return out

    # ------------------------------------------------------------------ #
    # devices: identifier, entity_name, internal_name, last_ip
    # ------------------------------------------------------------------ #
    def search_devices(
        self, q: str, limit: int = DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT identifier, entity_name, internal_name, last_ip "
            "FROM devices "
            "WHERE LOWER(identifier) LIKE LOWER(?) ESCAPE '\\' "
            "   OR LOWER(COALESCE(entity_name, '')) LIKE LOWER(?) ESCAPE '\\' "
            "   OR LOWER(COALESCE(internal_name, '')) LIKE LOWER(?) ESCAPE '\\' "
            "   OR LOWER(COALESCE(last_ip, '')) LIKE LOWER(?) ESCAPE '\\' "
            "ORDER BY last_seen DESC "
            "LIMIT ?",
            (
                _pattern(q), _pattern(q),
                _pattern(q), _pattern(q),
                limit,
            ),
        )
        return self._rows_to_dicts(cur)

    # ------------------------------------------------------------------ #
    # whitelisted_devices: identifier, entity_name
    # ------------------------------------------------------------------ #
    def search_whitelisted_devices(
        self, q: str, limit: int = DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT identifier, entity_name "
            "FROM whitelisted_devices "
            "WHERE LOWER(identifier) LIKE LOWER(?) ESCAPE '\\' "
            "   OR LOWER(COALESCE(entity_name, '')) LIKE LOWER(?) ESCAPE '\\' "
            "ORDER BY timestamp DESC "
            "LIMIT ?",
            (_pattern(q), _pattern(q), limit),
        )
        return self._rows_to_dicts(cur)

    # ------------------------------------------------------------------ #
    # change_requests: change_id, title
    # ------------------------------------------------------------------ #
    def search_changes(
        self, q: str, limit: int = DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT change_id, title, status, type "
            "FROM change_requests "
            "WHERE LOWER(change_id) LIKE LOWER(?) ESCAPE '\\' "
            "   OR LOWER(title) LIKE LOWER(?) ESCAPE '\\' "
            "ORDER BY timestamp DESC "
            "LIMIT ?",
            (_pattern(q), _pattern(q), limit),
        )
        return self._rows_to_dicts(cur)

    # ------------------------------------------------------------------ #
    # approvals: request_id, tool_name, requested_by
    # ------------------------------------------------------------------ #
    def search_approvals(
        self, q: str, limit: int = DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT request_id, tool_name, requested_by, status "
            "FROM approvals "
            "WHERE LOWER(request_id) LIKE LOWER(?) ESCAPE '\\' "
            "   OR LOWER(tool_name) LIKE LOWER(?) ESCAPE '\\' "
            "   OR LOWER(requested_by) LIKE LOWER(?) ESCAPE '\\' "
            "ORDER BY timestamp DESC "
            "LIMIT ?",
            (_pattern(q), _pattern(q), _pattern(q), limit),
        )
        return self._rows_to_dicts(cur)

    # ------------------------------------------------------------------ #
    # principals: name
    # ------------------------------------------------------------------ #
    def search_principals(
        self, q: str, limit: int = DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT name, kind, is_active "
            "FROM principals "
            "WHERE LOWER(name) LIKE LOWER(?) ESCAPE '\\' "
            "ORDER BY name ASC "
            "LIMIT ?",
            (_pattern(q), limit),
        )
        return self._rows_to_dicts(cur)

    # ------------------------------------------------------------------ #
    # roles: name
    # ------------------------------------------------------------------ #
    def search_roles(
        self, q: str, limit: int = DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT name, description "
            "FROM roles "
            "WHERE LOWER(name) LIKE LOWER(?) ESCAPE '\\' "
            "ORDER BY name ASC "
            "LIMIT ?",
            (_pattern(q), limit),
        )
        return self._rows_to_dicts(cur)

    # ------------------------------------------------------------------ #
    # permissions: code
    # ------------------------------------------------------------------ #
    def search_permissions(
        self, q: str, limit: int = DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT code, description "
            "FROM permissions "
            "WHERE LOWER(code) LIKE LOWER(?) ESCAPE '\\' "
            "ORDER BY code ASC "
            "LIMIT ?",
            (_pattern(q), limit),
        )
        return self._rows_to_dicts(cur)


__all__ = [
    "DEFAULT_LIMIT",
    "SearchRepository",
    "escape_like",
]
