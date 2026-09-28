"""
Approval-Datenmodell.

Eine ApprovalRequest beschreibt eine konkrete Freigabe-Anfrage fuer
einen Tool-Aufruf, den die Policy Engine als APPROVAL_REQUIRED
eingestuft hat.

DB ist die Quelle der Wahrheit. Telegram ist nur Kanal.

Konventionen:
- Alle Zeitstempel UTC-aware, ISO-8601-Strings.
- Naive datetime wird abgelehnt (fail closed).
- ApprovalRequest ist frozen (unveraenderlich).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timezone
from enum import Enum
from typing import Any, Mapping


class ApprovalStatus(str, Enum):
    """Erlaubte Status-Werte. DB speichert sie als TEXT (klein)."""

    PENDING = "pending"
    GRANTED = "granted"
    REJECTED = "rejected"
    EXPIRED = "expired"


# ---------------------------------------------------------------------- #
# Zeit-Helfer
# ---------------------------------------------------------------------- #

def utc_now_iso() -> str:
    """Aktueller UTC-Zeitstempel als ISO-8601-String."""
    return datetime.now(UTC).isoformat()


def require_utc_iso(value: str, field_name: str) -> str:
    """
    Prueft, dass value ein UTC-aware ISO-8601-String ist.
    Naive oder unparsebare Werte -> ValueError (fail closed).
    """
    if not isinstance(value, str) or not value:
        raise ValueError(
            f"ApprovalRequest: {field_name} muss ISO-8601-String sein"
        )
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(
            f"ApprovalRequest: {field_name} nicht parsebar: {value!r}"
        ) from exc
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(
            f"ApprovalRequest: {field_name} muss timezone-aware sein"
        )
    return value


# ---------------------------------------------------------------------- #
# ApprovalRequest
# ---------------------------------------------------------------------- #

@dataclass(frozen=True)
class ApprovalRequest:
    """
    Eine Freigabe-Anfrage.

    Pflichtfelder: request_id, timestamp, tool_name, args_json,
    requested_by, status, created_at.
    Optionale Felder: reason, risk_category, risk_score, event_id,
    decided_at, decided_by, decision_reason, expires_at.
    id wird von SQLite vergeben und beim Lesen mitgegeben.
    """

    request_id: str
    timestamp: str
    tool_name: str
    args_json: str
    requested_by: str
    status: ApprovalStatus
    created_at: str
    reason: str | None = None
    risk_category: str | None = None
    risk_score: float | None = None
    event_id: str | None = None
    decided_at: str | None = None
    decided_by: str | None = None
    decision_reason: str | None = None
    expires_at: str | None = None
    row_id: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or not self.request_id:
            raise ValueError("ApprovalRequest: request_id darf nicht leer sein")
        if not isinstance(self.tool_name, str) or not self.tool_name:
            raise ValueError("ApprovalRequest: tool_name darf nicht leer sein")
        if not isinstance(self.requested_by, str) or not self.requested_by:
            raise ValueError(
                "ApprovalRequest: requested_by darf nicht leer sein"
            )
        if not isinstance(self.status, ApprovalStatus):
            raise ValueError(
                f"ApprovalRequest: status muss ApprovalStatus sein, "
                f"nicht {type(self.status).__name__}"
            )
        require_utc_iso(self.timestamp, "timestamp")
        require_utc_iso(self.created_at, "created_at")
        if self.decided_at is not None:
            require_utc_iso(self.decided_at, "decided_at")
        if self.expires_at is not None:
            require_utc_iso(self.expires_at, "expires_at")
        # args_json muss valides JSON sein (Objekt oder Array)
        try:
            parsed = json.loads(self.args_json)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "ApprovalRequest: args_json ist kein valides JSON"
            ) from exc
        if not isinstance(parsed, (dict, list)):
            raise ValueError(
                "ApprovalRequest: args_json muss Objekt oder Array sein"
            )

    # ------------------------------------------------------------------ #
    # Serialisierung
    # ------------------------------------------------------------------ #

    def args(self) -> Any:
        """args_json als Python-Objekt (dict oder list)."""
        return json.loads(self.args_json)

    def to_dict(self) -> dict[str, Any]:
        """Repraesentation fuer Audit/Ausgabe. Status als String."""
        return {
            "id": self.row_id,
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "args": self.args(),
            "requested_by": self.requested_by,
            "reason": self.reason,
            "risk_category": self.risk_category,
            "risk_score": self.risk_score,
            "event_id": self.event_id,
            "status": self.status.value,
            "decided_at": self.decided_at,
            "decided_by": self.decided_by,
            "decision_reason": self.decision_reason,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
        }

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "ApprovalRequest":
        """Baut eine ApprovalRequest aus einer sqlite3.Row / Mapping."""
        return cls(
            row_id=row["id"],
            request_id=row["request_id"],
            timestamp=row["timestamp"],
            tool_name=row["tool_name"],
            args_json=row["args_json"],
            requested_by=row["requested_by"],
            reason=row["reason"],
            risk_category=row["risk_category"],
            risk_score=row["risk_score"],
            event_id=row["event_id"],
            status=ApprovalStatus(row["status"]),
            decided_at=row["decided_at"],
            decided_by=row["decided_by"],
            decision_reason=row["decision_reason"],
            expires_at=row["expires_at"],
            created_at=row["created_at"],
        )


__all__ = [
    "ApprovalStatus",
    "ApprovalRequest",
    "utc_now_iso",
    "require_utc_iso",
]
