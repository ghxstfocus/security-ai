"""
Repository fuer change_requests.

Konvention wie ApprovalRepository / DeviceRepository:
- Der Konstruktor bekommt eine offene sqlite3.Connection.
- connect/apply_migrations/close liegen beim Aufrufer.
- row_factory = sqlite3.Row wird hier defensiv sichergestellt.

change_id-Format: CHG-YYYY-NNNNN, jahresweise, atomar vergeben.
SQLite ist Quelle der Wahrheit. JSON-Export via parser.py.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from core.changes.models import (
    ChangeRequest,
    ChangeStatus,
    ChangeType,
    utc_now_iso,
)


_PREFIX = "CHG"


class ChangeRepositoryError(RuntimeError):
    """Fachlicher Fehler im Change-Repository."""


class ChangeNotFoundError(ChangeRepositoryError):
    """change_id existiert nicht."""


class ChangeStateError(ChangeRepositoryError):
    """Uebergang nicht erlaubt."""


# Erlaubte Zustandsuebergaenge (Quelle: models.ChangeStatus)
_ALLOWED_TRANSITIONS: dict[ChangeStatus, frozenset[ChangeStatus]] = {
    ChangeStatus.DRAFT: frozenset({
        ChangeStatus.TESTING,
        ChangeStatus.PENDING_REVIEW,
        ChangeStatus.REJECTED,
    }),
    ChangeStatus.TESTING: frozenset({
        ChangeStatus.PENDING_REVIEW,
        ChangeStatus.REJECTED,
    }),
    ChangeStatus.PENDING_REVIEW: frozenset({
        ChangeStatus.APPROVED,
        ChangeStatus.REJECTED,
    }),
    ChangeStatus.APPROVED: frozenset({
        ChangeStatus.DEPLOYED,
        ChangeStatus.REJECTED,
    }),
    ChangeStatus.DEPLOYED: frozenset({
        ChangeStatus.ROLLED_BACK,
    }),
    ChangeStatus.ROLLED_BACK: frozenset(),
    ChangeStatus.REJECTED: frozenset(),
}


class ChangeRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        if self._conn.row_factory is None:
            self._conn.row_factory = sqlite3.Row

    # ------------------------------------------------------------------ #
    # change_id-Vergabe
    # ------------------------------------------------------------------ #

    def _next_change_id(self, year: int) -> str:
        pattern = f"{_PREFIX}-{year:04d}-%"
        cur = self._conn.execute(
            "SELECT change_id FROM change_requests "
            "WHERE change_id LIKE ? "
            "ORDER BY change_id DESC LIMIT 1",
            (pattern,),
        )
        row = cur.fetchone()
        if row is None:
            return f"{_PREFIX}-{year:04d}-00001"
        last = row["change_id"]
        try:
            n = int(last.rsplit("-", 1)[1])
        except (IndexError, ValueError) as exc:
            raise ChangeRepositoryError(
                f"change_id nicht parsebar: {last!r}"
            ) from exc
        return f"{_PREFIX}-{year:04d}-{n + 1:05d}"

    # ------------------------------------------------------------------ #
    # create / get
    # ------------------------------------------------------------------ #

    def create(
        self,
        *,
        title: str,
        description: str,
        requested_by: str,
        type: ChangeType,
        status: ChangeStatus = ChangeStatus.DRAFT,
        diff_or_patch: str | None = None,
        files_affected: list[str] | None = None,
        rollback_plan: str | None = None,
        test_plan: str | None = None,
        related_approval_id: str | None = None,
        related_event_id: str | None = None,
        risk_category: str | None = None,
        risk_score: float | None = None,
        timestamp: str | None = None,
    ) -> ChangeRequest:
        if not isinstance(type, ChangeType):
            raise ChangeRepositoryError("type muss ChangeType sein")
        if not isinstance(status, ChangeStatus):
            raise ChangeRepositoryError("status muss ChangeStatus sein")
        if files_affected is not None and not isinstance(
                files_affected, list):
            raise ChangeRepositoryError(
                "files_affected muss list[str] sein"
            )

        ts = timestamp or utc_now_iso()
        created = utc_now_iso()
        files_json = (
            json.dumps(files_affected) if files_affected is not None
            else None
        )

        try:
            self._conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError:
            pass

        try:
            year = datetime.fromisoformat(ts).year
            change_id = self._next_change_id(year)
            self._conn.execute(
                "INSERT INTO change_requests ("
                " change_id, timestamp, title, description,"
                " requested_by, status, type, diff_or_patch,"
                " files_affected, rollback_plan, test_plan,"
                " related_approval_id, related_event_id,"
                " risk_category, risk_score, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    change_id,
                    ts,
                    title,
                    description,
                    requested_by,
                    status.value,
                    type.value,
                    diff_or_patch,
                    files_json,
                    rollback_plan,
                    test_plan,
                    related_approval_id,
                    related_event_id,
                    risk_category,
                    risk_score,
                    created,
                ),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

        return self.get(change_id)

    def get(self, change_id: str) -> ChangeRequest:
        cur = self._conn.execute(
            "SELECT * FROM change_requests WHERE change_id = ?",
            (change_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise ChangeNotFoundError(
                f"change_id {change_id!r} nicht gefunden"
            )
        return ChangeRequest.from_row(row)

    # ------------------------------------------------------------------ #
    # Auflisten
    # ------------------------------------------------------------------ #

    def list_pending(self) -> list[ChangeRequest]:
        """
        Alles, was auf eine Entscheidung wartet:
        PENDING_REVIEW.
        """
        cur = self._conn.execute(
            "SELECT * FROM change_requests WHERE status = ? "
            "ORDER BY id ASC",
            (ChangeStatus.PENDING_REVIEW.value,),
        )
        return [ChangeRequest.from_row(r) for r in cur.fetchall()]

    def list_by_status(
        self,
        status: ChangeStatus,
        limit: int | None = None,
    ) -> list[ChangeRequest]:
        if not isinstance(status, ChangeStatus):
            raise ChangeRepositoryError("status muss ChangeStatus sein")
        sql = (
            "SELECT * FROM change_requests WHERE status = ? "
            "ORDER BY id DESC"
        )
        params: list[Any] = [status.value]
        if limit is not None:
            if not isinstance(limit, int) or limit <= 0:
                raise ChangeRepositoryError("limit muss positive int sein")
            sql += " LIMIT ?"
            params.append(limit)
        cur = self._conn.execute(sql, params)
        return [ChangeRequest.from_row(r) for r in cur.fetchall()]

    def list_all(self, limit: int | None = None) -> list[ChangeRequest]:
        sql = "SELECT * FROM change_requests ORDER BY id DESC"
        params: list[Any] = []
        if limit is not None:
            if not isinstance(limit, int) or limit <= 0:
                raise ChangeRepositoryError("limit muss positive int sein")
            sql += " LIMIT ?"
            params.append(limit)
        cur = self._conn.execute(sql, params)
        return [ChangeRequest.from_row(r) for r in cur.fetchall()]

    def count_by_status(self) -> dict[ChangeStatus, int]:
        cur = self._conn.execute(
            "SELECT status, COUNT(*) AS n FROM change_requests "
            "GROUP BY status"
        )
        result: dict[ChangeStatus, int] = {s: 0 for s in ChangeStatus}
        for row in cur.fetchall():
            try:
                s = ChangeStatus(row["status"])
            except ValueError:
                continue
            result[s] = int(row["n"])
        return result

    # ------------------------------------------------------------------ #
    # Zustandsuebergaenge
    # ------------------------------------------------------------------ #

    def transition(
        self,
        change_id: str,
        new_status: ChangeStatus,
        decided_by: str | None = None,
        reason: str | None = None,
    ) -> ChangeRequest:
        """
        Setzt einen neuen Status, prueft Uebergang.
        Setzt decided_at/decided_by/decision_reason fuer die
        Endzustaende APPROVED/REJECTED/ROLLED_BACK.
        Setzt deployed_at bei DEPLOYED, rolled_back_at bei ROLLED_BACK.
        """
        if not isinstance(new_status, ChangeStatus):
            raise ChangeRepositoryError("new_status muss ChangeStatus sein")

        current = self.get(change_id)
        allowed = _ALLOWED_TRANSITIONS.get(current.status, frozenset())
        if new_status not in allowed:
            raise ChangeStateError(
                f"Uebergang {current.status.value} -> "
                f"{new_status.value} nicht erlaubt"
            )

        now = utc_now_iso()
        sets: list[str] = ["status = ?"]
        params: list[Any] = [new_status.value]

        if new_status in (
            ChangeStatus.APPROVED,
            ChangeStatus.REJECTED,
            ChangeStatus.ROLLED_BACK,
        ):
            sets += ["decided_at = ?"]
            params.append(now)
            if decided_by is not None:
                sets += ["decided_by = ?"]
                params.append(decided_by)
            if reason is not None:
                sets += ["decision_reason = ?"]
                params.append(reason)

        if new_status is ChangeStatus.DEPLOYED:
            sets += ["deployed_at = ?"]
            params.append(now)

        if new_status is ChangeStatus.ROLLED_BACK:
            sets += ["rolled_back_at = ?"]
            params.append(now)

        params += [change_id, current.status.value]
        sql = (
            "UPDATE change_requests SET " + ", ".join(sets)
            + " WHERE change_id = ? AND status = ?"
        )
        cur = self._conn.execute(sql, params)
        if (cur.rowcount or 0) == 0:
            self._conn.rollback()
            raise ChangeStateError(
                f"change_id {change_id!r} konnte nicht uebergehen "
                f"(Race?)"
            )
        self._conn.commit()
        return self.get(change_id)

    # ------------------------------------------------------------------ #
    # Feld-Updates (nicht Status)
    # ------------------------------------------------------------------ #

    _UPDATABLE_FIELDS = frozenset({
        "title", "description", "diff_or_patch", "files_affected",
        "rollback_plan", "test_plan", "related_approval_id",
        "related_event_id", "risk_category", "risk_score",
    })

    def update_fields(self, change_id: str, **fields: Any) -> ChangeRequest:
        """
        Aktualisiert inhaltliche Felder (nicht status, nicht change_id,
        nicht timestamp, nicht created_at). Unbekannte Felder -> Fehler.
        """
        if not fields:
            return self.get(change_id)
        bad = set(fields) - self._UPDATABLE_FIELDS
        if bad:
            raise ChangeRepositoryError(
                f"nicht aktualisierbare Felder: {sorted(bad)}"
            )

        current = self.get(change_id)

        sets: list[str] = []
        params: list[Any] = []
        for k, v in fields.items():
            if k == "files_affected":
                v = json.dumps(v) if v is not None else None
            sets.append(f"{k} = ?")
            params.append(v)
        params.append(change_id)
        sql = (
            "UPDATE change_requests SET " + ", ".join(sets)
            + " WHERE change_id = ?"
        )
        self._conn.execute(sql, params)
        self._conn.commit()
        return self.get(change_id)


__all__ = [
    "ChangeRepository",
    "ChangeRepositoryError",
    "ChangeNotFoundError",
    "ChangeStateError",
]
