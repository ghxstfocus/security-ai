# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Repository fuer approvals.

Konvention wie DeviceRepository:
- Der Konstruktor bekommt eine offene sqlite3.Connection.
- connect/apply_migrations/close liegen beim Aufrufer.
- row_factory = sqlite3.Row wird hier sichergestellt (defensiv).

request_id-Format: APR-YYYY-NNNNN, jahresweise, atomar vergeben.
DB ist Quelle der Wahrheit, Telegram ist nur Kanal.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from core.approval.models import (
    ApprovalRequest,
    ApprovalStatus,
    utc_now_iso,
)

_PREFIX = "APR"


class ApprovalRepositoryError(RuntimeError):
    """Fachlicher Fehler im Approval-Repository."""


class ApprovalNotFoundError(ApprovalRepositoryError):
    """request_id existiert nicht."""


class ApprovalStateError(ApprovalRepositoryError):
    """Uebergang nicht erlaubt (z. B. bereits entschieden)."""


class ApprovalRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        # Sicherstellen, dass rows als sqlite3.Row zurueckkommen.
        if self._conn.row_factory is None:
            self._conn.row_factory = sqlite3.Row

    # ------------------------------------------------------------------ #
    # request_id-Vergabe
    # ------------------------------------------------------------------ #

    def _next_request_id(self, year: int) -> str:
        """
        Naechste freie request_id fuer das Jahr.
        Erwartet eine offene Transaktion (BEGIN IMMEDIATE).
        """
        pattern = f"{_PREFIX}-{year:04d}-%"
        cur = self._conn.execute(
            "SELECT request_id FROM approvals "
            "WHERE request_id LIKE ? "
            "ORDER BY request_id DESC LIMIT 1",
            (pattern,),
        )
        row = cur.fetchone()
        if row is None:
            return f"{_PREFIX}-{year:04d}-00001"
        last = row["request_id"]
        try:
            n = int(last.rsplit("-", 1)[1])
        except (IndexError, ValueError) as exc:
            raise ApprovalRepositoryError(
                f"request_id nicht parsebar: {last!r}"
            ) from exc
        return f"{_PREFIX}-{year:04d}-{n + 1:05d}"

    # ------------------------------------------------------------------ #
    # create / get
    # ------------------------------------------------------------------ #

    def create(
        self,
        *,
        tool_name: str,
        args: dict[str, Any] | list[Any],
        requested_by: str,
        reason: str | None = None,
        risk_category: str | None = None,
        risk_score: float | None = None,
        event_id: str | None = None,
        expires_at: str | None = None,
        timestamp: str | None = None,
    ) -> ApprovalRequest:
        """
        Legt eine neue ApprovalRequest an (Status PENDING).
        Vergibt request_id atomar. Liefert die gespeicherte Request.
        """
        if not isinstance(tool_name, str) or not tool_name:
            raise ApprovalRepositoryError("tool_name darf nicht leer sein")
        if not isinstance(requested_by, str) or not requested_by:
            raise ApprovalRepositoryError("requested_by darf nicht leer sein")
        if not isinstance(args, (dict, list)):
            raise ApprovalRepositoryError("args muss dict oder list sein")

        ts = timestamp or utc_now_iso()
        created = utc_now_iso()
        args_json = json.dumps(args, sort_keys=True)

        # Atomare Vergabe: BEGIN IMMEDIATE + MAX-Selektion + INSERT.
        try:
            self._conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError:
            # Schon in einer Transaktion -> so lassen, Aufrufer kuemmert sich.
            pass

        try:
            year = datetime.fromisoformat(ts).year
            request_id = self._next_request_id(year)
            self._conn.execute(
                "INSERT INTO approvals ("
                " request_id, timestamp, tool_name, args_json,"
                " requested_by, reason, risk_category, risk_score,"
                " event_id, status, expires_at, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    request_id,
                    ts,
                    tool_name,
                    args_json,
                    requested_by,
                    reason,
                    risk_category,
                    risk_score,
                    event_id,
                    ApprovalStatus.PENDING.value,
                    expires_at,
                    created,
                ),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

        return self.get(request_id)

    def get(self, request_id: str) -> ApprovalRequest:
        cur = self._conn.execute(
            "SELECT * FROM approvals WHERE request_id = ?",
            (request_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise ApprovalNotFoundError(
                f"request_id {request_id!r} nicht gefunden"
            )
        return ApprovalRequest.from_row(row)

    # ------------------------------------------------------------------ #
    # Auflisten
    # ------------------------------------------------------------------ #

    def list_pending(self) -> list[ApprovalRequest]:
        cur = self._conn.execute(
            "SELECT * FROM approvals WHERE status = ? "
            "ORDER BY id ASC",
            (ApprovalStatus.PENDING.value,),
        )
        return [ApprovalRequest.from_row(r) for r in cur.fetchall()]

    def list_all(
        self,
        status: ApprovalStatus | None = None,
        limit: int | None = None,
    ) -> list[ApprovalRequest]:
        sql = "SELECT * FROM approvals"
        params: list[Any] = []
        if status is not None:
            if not isinstance(status, ApprovalStatus):
                raise ApprovalRepositoryError(
                    "status muss ApprovalStatus sein"
                )
            sql += " WHERE status = ?"
            params.append(status.value)
        sql += " ORDER BY id DESC"
        if limit is not None:
            if not isinstance(limit, int) or limit <= 0:
                raise ApprovalRepositoryError(
                    "limit muss positive int sein"
                )
            sql += " LIMIT ?"
            params.append(limit)
        cur = self._conn.execute(sql, params)
        return [ApprovalRequest.from_row(r) for r in cur.fetchall()]

    def list_by_event(self, event_id: str) -> list[ApprovalRequest]:
        if not isinstance(event_id, str) or not event_id:
            raise ApprovalRepositoryError("event_id darf nicht leer sein")
        cur = self._conn.execute(
            "SELECT * FROM approvals WHERE event_id = ? "
            "ORDER BY id ASC",
            (event_id,),
        )
        return [ApprovalRequest.from_row(r) for r in cur.fetchall()]

    def count_by_status(self) -> dict[ApprovalStatus, int]:
        cur = self._conn.execute(
            "SELECT status, COUNT(*) AS n FROM approvals GROUP BY status"
        )
        result: dict[ApprovalStatus, int] = {
            s: 0 for s in ApprovalStatus
        }
        for row in cur.fetchall():
            try:
                s = ApprovalStatus(row["status"])
            except ValueError:
                continue
            result[s] = int(row["n"])
        return result

    # ------------------------------------------------------------------ #
    # Entscheiden / Ablaufen
    # ------------------------------------------------------------------ #

    def decide(
        self,
        request_id: str,
        status: ApprovalStatus,
        decided_by: str,
        decision_reason: str | None = None,
    ) -> ApprovalRequest:
        """
        Setzt eine PENDING-Request auf GRANTED oder REJECTED.
        Nur diese zwei Ziele sind erlaubt. Anderer Zustand -> Fehler.
        """
        if status not in (ApprovalStatus.GRANTED, ApprovalStatus.REJECTED):
            raise ApprovalRepositoryError(
                "decide akzeptiert nur GRANTED oder REJECTED"
            )
        if not isinstance(decided_by, str) or not decided_by:
            raise ApprovalRepositoryError("decided_by darf nicht leer sein")

        current = self.get(request_id)
        if current.status is not ApprovalStatus.PENDING:
            raise ApprovalStateError(
                f"request_id {request_id!r} ist {current.status.value}, "
                f"nicht pending"
            )

        decided_at = utc_now_iso()
        cur = self._conn.execute(
            "UPDATE approvals SET status = ?, decided_at = ?, "
            "decided_by = ?, decision_reason = ? "
            "WHERE request_id = ? AND status = ?",
            (
                status.value,
                decided_at,
                decided_by,
                decision_reason,
                request_id,
                ApprovalStatus.PENDING.value,
            ),
        )
        if (cur.rowcount or 0) == 0:
            self._conn.rollback()
            raise ApprovalStateError(
                f"request_id {request_id!r} konnte nicht entschieden "
                f"werden (Race?)"
            )
        self._conn.commit()
        return self.get(request_id)

    def expire_overdue(self, now_iso: str | None = None) -> int:
        """
        Setzt alle PENDING-Requests mit expires_at < now auf EXPIRED.
        Liefert die Anzahl der geaenderten Zeilen.
        """
        now = now_iso or utc_now_iso()
        cur = self._conn.execute(
            "UPDATE approvals SET status = ?, decided_at = ?, "
            "decision_reason = COALESCE(decision_reason, 'expired') "
            "WHERE status = ? AND expires_at IS NOT NULL "
            "AND expires_at < ?",
            (
                ApprovalStatus.EXPIRED.value,
                now,
                ApprovalStatus.PENDING.value,
                now,
            ),
        )
        n = cur.rowcount or 0
        self._conn.commit()
        return n


__all__ = [
    "ApprovalNotFoundError",
    "ApprovalRepository",
    "ApprovalRepositoryError",
    "ApprovalStateError",
]
