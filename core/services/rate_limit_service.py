"""
RateLimitService: SQLite-basiertes Rate-Limit pro Principal.

Zweck: /api/chat ist ein LLM-Konsum-Kanal. Ohne Limit
kann ein einzelner Principal den Container saettigen (DoS).

Design (Punkt 9, Auflagen 663-676):
- Key = principal_name (nicht Session-ID, nicht IP).
- Store = SQLite-Tabelle chat_rate_hits. Multi-Worker-fest
  (gunicorn mit 2 Workern, 16a).
- Jede erlaubte Anfrage erzeugt eine Zeile (principal_name,
  hit_at). hit_at als ISO-8601 UTC.
- Alte Zeilen werden bei jedem allow()-Aufruf geloescht
  (Haushaltung).
- BEGIN IMMEDIATE um die Zaehlen+Einfuegen-Sequenz
  (Auflage 669).
- Fail closed bei SQLite-Fehler (Auflage 664).
- Kein Audit, kein Log bei Treffer (Auflage 101/673).
- Kein Reset bei Logout (Auflage 674).
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone, UTC

from core.services import ServiceError

WINDOW_SECONDS = 60
MAX_REQUESTS = 10


class RateLimitServiceError(ServiceError):
    """Fachlicher Fehler im RateLimitService."""


class RateLimitService:
    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        window_seconds: int = WINDOW_SECONDS,
        max_requests: int = MAX_REQUESTS,
    ) -> None:
        if conn is None:
            raise RateLimitServiceError("conn ist Pflicht")
        if not isinstance(window_seconds, int) or window_seconds <= 0:
            raise RateLimitServiceError(
                "window_seconds muss positive int sein"
            )
        if not isinstance(max_requests, int) or max_requests <= 0:
            raise RateLimitServiceError(
                "max_requests muss positive int sein"
            )
        self._conn = conn
        self._window = window_seconds
        self._max = max_requests

    def allow(self, principal_name: str) -> tuple[bool, int]:
        """
        True, wenn Anfrage erlaubt.
        int = Retry-After-Sekunden (0 bei True).

        Fail closed: SQLite-Fehler -> (False, 0). Der
        Aufrufer (Route) gibt 500 zurueck, kein 429.
        """
        if not isinstance(principal_name, str) or not principal_name:
            raise RateLimitServiceError(
                "principal_name darf nicht leer sein"
            )
        now = datetime.now(UTC)
        window_start = now - timedelta(seconds=self._window)
        now_iso = now.isoformat()
        ws_iso = window_start.isoformat()
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            # Haushaltung: alte Zeilen loeschen.
            self._conn.execute(
                "DELETE FROM chat_rate_hits "
                "WHERE principal_name = ? AND hit_at < ?",
                (principal_name, ws_iso),
            )
            # Zaehlen im Fenster.
            cur = self._conn.execute(
                "SELECT COUNT(*) FROM chat_rate_hits "
                "WHERE principal_name = ? AND hit_at >= ?",
                (principal_name, ws_iso),
            )
            n = cur.fetchone()[0]
            if n >= self._max:
                # Retry-After: aeltester Eintrag im Fenster.
                cur = self._conn.execute(
                    "SELECT MIN(hit_at) FROM chat_rate_hits "
                    "WHERE principal_name = ? AND hit_at >= ?",
                    (principal_name, ws_iso),
                )
                oldest_iso = cur.fetchone()[0]
                retry = 1
                if isinstance(oldest_iso, str):
                    try:
                        oldest = datetime.fromisoformat(oldest_iso)
                        delta = self._window - (now - oldest).total_seconds()
                        retry = max(1, int(delta))
                    except ValueError:
                        retry = 1
                self._conn.execute("COMMIT")
                return (False, retry)
            self._conn.execute(
                "INSERT INTO chat_rate_hits "
                "(principal_name, hit_at) VALUES (?, ?)",
                (principal_name, now_iso),
            )
            self._conn.execute("COMMIT")
            return (True, 0)
        except sqlite3.Error:
            # Fail closed (Auflage 664). Rollback, dann
            # (False, 0). Route gibt 500.
            try:
                self._conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return (False, 0)


__all__ = [
    "MAX_REQUESTS",
    "WINDOW_SECONDS",
    "RateLimitService",
    "RateLimitServiceError",
]
