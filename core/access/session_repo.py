"""
Repositories fuer serverseitige Sessions und Login-Versuche.

Design:
- Konstruktor bekommt eine offene sqlite3.Connection.
  connect/apply_migrations/close liegen beim Aufrufer.
- row_factory = sqlite3.Row wird defensiv sichergestellt.
- Zeit-Helfer (utc_now, to_utc, to_iso) und Session
  kommen aus core.access.models.
- Keine Umlaute, mypy-konform (disallow_untyped_defs).
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

from core.access.models import (
    Session,
    to_iso,
    to_utc,
    utc_now,
)

# ---------------------------------------------------------------------- #
# Helfer
# ---------------------------------------------------------------------- #

def _ensure_row_factory(conn: sqlite3.Connection) -> None:
    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row


# ---------------------------------------------------------------------- #
# Fehler
# ---------------------------------------------------------------------- #

class SessionRepositoryError(RuntimeError):
    """Fachlicher Fehler im Session-Repository."""


# ---------------------------------------------------------------------- #
# SessionRepository
# ---------------------------------------------------------------------- #

class SessionRepository:
    """CRUD + Lifecycle fuer sessions."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        _ensure_row_factory(conn)

    # -------------------------------------------------------------- #
    # Lesen
    # -------------------------------------------------------------- #

    def get(self, session_id: str) -> Session | None:
        if not isinstance(session_id, str) or not session_id:
            return None
        cur = self._conn.execute(
            "SELECT id, principal_name, created_at, last_seen_at, "
            "revoked_at, ip, user_agent FROM sessions WHERE id = ?",
            (session_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return Session.from_row(row)

    # -------------------------------------------------------------- #
    # Schreiben
    # -------------------------------------------------------------- #

    def create(
        self,
        session_id: str,
        principal_name: str,
        *,
        ip: str | None = None,
        user_agent: str | None = None,
        now: datetime | str | None = None,
    ) -> Session:
        if not isinstance(session_id, str) or not session_id:
            raise SessionRepositoryError(
                "session_id darf nicht leer sein"
            )
        if not isinstance(principal_name, str) or not principal_name:
            raise SessionRepositoryError(
                "principal_name darf nicht leer sein"
            )
        ts = to_iso(now if now is not None else utc_now())
        try:
            self._conn.execute(
                "INSERT INTO sessions "
                "(id, principal_name, created_at, last_seen_at, "
                "revoked_at, ip, user_agent) "
                "VALUES (?, ?, ?, ?, NULL, ?, ?)",
                (session_id, principal_name, ts, ts, ip, user_agent),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            self._conn.rollback()
            msg = str(exc)
            if "FOREIGN KEY" in msg or \
                    "foreign key" in msg.lower():
                raise SessionRepositoryError(
                    f"Principal {principal_name!r} "
                    f"nicht gefunden"
                ) from exc
            raise SessionRepositoryError(
                f"Session {session_id!r} existiert bereits"
            ) from exc
        s = self.get(session_id)
        if s is None:
            raise SessionRepositoryError(
                "Session nach INSERT nicht lesbar"
            )
        return s

    def touch(
        self,
        session_id: str,
        *,
        ip: str | None = None,
        user_agent: str | None = None,
        now: datetime | str | None = None,
    ) -> bool:
        """
        Aktualisiert last_seen_at (und optional ip/user_agent).
        Liefert True bei Erfolg, False bei unbekannter oder
        widerrufener Session.
        """
        ts = to_iso(now if now is not None else utc_now())
        if ip is None and user_agent is None:
            cur = self._conn.execute(
                "UPDATE sessions SET last_seen_at = ? "
                "WHERE id = ? AND revoked_at IS NULL",
                (ts, session_id),
            )
        else:
            cur = self._conn.execute(
                "UPDATE sessions SET last_seen_at = ?, "
                "ip = COALESCE(?, ip), "
                "user_agent = COALESCE(?, user_agent) "
                "WHERE id = ? AND revoked_at IS NULL",
                (ts, ip, user_agent, session_id),
            )
        n = cur.rowcount or 0
        self._conn.commit()
        return n > 0

    def revoke(
        self,
        session_id: str,
        *,
        now: datetime | str | None = None,
    ) -> bool:
        """
        Markiert Session als widerrufen (idempotent).
        Liefert True, wenn eine aktive Session widerrufen
        wurde; False, wenn nicht vorhanden oder schon
        widerrufen.
        """
        ts = to_iso(now if now is not None else utc_now())
        cur = self._conn.execute(
            "UPDATE sessions SET revoked_at = ? "
            "WHERE id = ? AND revoked_at IS NULL",
            (ts, session_id),
        )
        n = cur.rowcount or 0
        self._conn.commit()
        return n > 0

    def revoke_all_for_principal(
        self,
        principal_name: str,
        *,
        now: datetime | str | None = None,
    ) -> int:
        """
        Widerruft alle aktiven Sessions eines Principals.
        Liefert die Anzahl der widerrufenen Sessions.
        Wird von AccessService.set_password (Auflage 14)
        aufgerufen.
        """
        if not isinstance(principal_name, str) or not principal_name:
            return 0
        ts = to_iso(now if now is not None else utc_now())
        cur = self._conn.execute(
            "UPDATE sessions SET revoked_at = ? "
            "WHERE principal_name = ? AND revoked_at IS NULL",
            (ts, principal_name),
        )
        n = cur.rowcount or 0
        self._conn.commit()
        return n

    # -------------------------------------------------------------- #
    # Cleanup (Phase 3.6.15)
    # -------------------------------------------------------------- #

    def purge_expired(
        self,
        *,
        before: datetime | str | None = None,
    ) -> int:
        """
        Loescht Sessions, die entweder alt-widerrufen sind
        (revoked_at < cutoff) oder deren last_seen_at vor
        cutoff liegt.

        Default fuer cutoff: jetzt - 30 Tage.
        Frisch widerrufene Sessions bleiben erhalten
        (Audit-Nachweis, Auflage 25).
        Liefert Anzahl geloeschter Zeilen.
        """
        if before is None:
            cutoff = utc_now() - timedelta(days=30)
        else:
            cutoff = to_utc(before)
        ts = cutoff.isoformat()
        cur = self._conn.execute(
            "DELETE FROM sessions "
            "WHERE (revoked_at IS NOT NULL AND revoked_at < ?) "
            "   OR last_seen_at < ?",
            (ts, ts),
        )
        n = cur.rowcount or 0
        self._conn.commit()
        return n


# ---------------------------------------------------------------------- #
# LoginAttemptRepository
# ---------------------------------------------------------------------- #

class LoginAttemptRepository:
    """
    Schreibt Login-Versuche und zaehlt Fehlversuche
    (fuer Rate-Limit auf /login, pro IP).
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        _ensure_row_factory(conn)

    def record(
        self,
        *,
        ip: str,
        principal_name: str | None = None,
        success: bool,
        now: datetime | str | None = None,
    ) -> None:
        if not isinstance(ip, str) or not ip:
            raise SessionRepositoryError(
                "ip darf nicht leer sein"
            )
        ts = to_iso(now if now is not None else utc_now())
        self._conn.execute(
            "INSERT INTO login_attempts "
            "(ip, principal_name, attempted_at, success) "
            "VALUES (?, ?, ?, ?)",
            (ip, principal_name, ts, 1 if success else 0),
        )
        self._conn.commit()

    def count_recent_failures(
        self,
        ip: str,
        *,
        window_seconds: int = 900,
        now: datetime | str | None = None,
    ) -> int:
        """
        Zaehlt fehlgeschlagene Login-Versuche pro IP im
        Zeitfenster. Default 900 s = 15 min.
        """
        if not isinstance(ip, str) or not ip:
            return 0
        if not isinstance(window_seconds, int) or window_seconds <= 0:
            raise SessionRepositoryError(
                "window_seconds muss positive int sein"
            )
        cutoff = (to_utc(now if now is not None else utc_now())
                  - timedelta(seconds=window_seconds))
        cur = self._conn.execute(
            "SELECT COUNT(*) AS n FROM login_attempts "
            "WHERE ip = ? AND success = 0 AND attempted_at >= ?",
            (ip, cutoff.isoformat()),
        )
        row = cur.fetchone()
        if row is None:
            return 0
        return int(row["n"])

    def purge_older_than(
        self,
        *,
        days: int = 30,
        now: datetime | str | None = None,
    ) -> int:
        """
        Loescht Login-Versuche, die aelter als 'days' Tage
        sind. Default 30 Tage. Fuer Phase 3.6.15.
        """
        if not isinstance(days, int) or days <= 0:
            raise SessionRepositoryError(
                "days muss positive int sein"
            )
        cutoff = (to_utc(now if now is not None else utc_now())
                  - timedelta(days=days))
        cur = self._conn.execute(
            "DELETE FROM login_attempts WHERE attempted_at < ?",
            (cutoff.isoformat(),),
        )
        n = cur.rowcount or 0
        self._conn.commit()
        return n


__all__ = [
    "LoginAttemptRepository",
    "SessionRepository",
    "SessionRepositoryError",
]
