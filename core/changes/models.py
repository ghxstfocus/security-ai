"""
Change-Request-Datenmodell.

Ein ChangeRequest beschreibt einen strukturierten Aenderungsantrag
(z. B. Firewall-Regel, Policy-Anpassung, Config-Aenderung).

SQLite ist Quelle der Wahrheit. JSON-Export via parser.py.

Konventionen:
- Alle Zeitstempel UTC-aware, ISO-8601-Strings.
- Naive datetime wird abgelehnt (fail closed).
- ChangeRequest ist frozen (unveraenderlich).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping


class ChangeStatus(str, Enum):
    """
    Status eines Change Requests.

    Konsistent mit docs/PROTOCOL.md.

    Fluss:
        DRAFT -> TESTING -> PENDING_REVIEW -> APPROVED -> DEPLOYED
        Jederzeit: REJECTED
        Aus DEPLOYED: ROLLED_BACK
    """

    DRAFT = "draft"
    TESTING = "testing"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    DEPLOYED = "deployed"
    ROLLED_BACK = "rolled_back"
    REJECTED = "rejected"


class ChangeType(str, Enum):
    """
    Typ des Change Requests.

    Der Applier (spaeter in harness/versioning/) entscheidet anhand
    des Typs, welche Aktion ausgefuehrt wird.
    """

    CONFIG_CHANGE = "config_change"
    CODE_CHANGE = "code_change"
    POLICY_CHANGE = "policy_change"
    FIREWALL_CHANGE = "firewall_change"
    DEVICE_WHITELIST_CHANGE = "device_whitelist_change"


# ---------------------------------------------------------------------- #
# Zeit-Helfer
# ---------------------------------------------------------------------- #

def utc_now_iso() -> str:
    """Aktueller UTC-Zeitstempel als ISO-8601-String."""
    return datetime.now(timezone.utc).isoformat()


def require_utc_iso(value: str, field_name: str) -> str:
    """
    Prueft, dass value ein UTC-aware ISO-8601-String ist.
    Naive oder unparsebare Werte -> ValueError (fail closed).
    """
    if not isinstance(value, str) or not value:
        raise ValueError(
            f"ChangeRequest: {field_name} muss ISO-8601-String sein"
        )
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(
            f"ChangeRequest: {field_name} nicht parsebar: {value!r}"
        ) from exc
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(
            f"ChangeRequest: {field_name} muss timezone-aware sein"
        )
    return value


def _require_str(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"ChangeRequest: {field_name} darf nicht leer sein"
        )
    return value


def _require_opt_utc_iso(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return require_utc_iso(value, field_name)


# ---------------------------------------------------------------------- #
# ChangeRequest
# ---------------------------------------------------------------------- #

@dataclass(frozen=True)
class ChangeRequest:
    """
    Ein Aenderungsantrag.

    Pflicht: change_id, timestamp, title, description, requested_by,
    status, type, created_at.
    Optional: alles ab diff_or_patch.
    row_id wird von SQLite vergeben und beim Lesen mitgegeben.
    """

    change_id: str
    timestamp: str
    title: str
    description: str
    requested_by: str
    status: ChangeStatus
    type: ChangeType
    created_at: str
    diff_or_patch: str | None = None
    files_affected: list[str] | None = None
    rollback_plan: str | None = None
    test_plan: str | None = None
    related_approval_id: str | None = None
    related_event_id: str | None = None
    risk_category: str | None = None
    risk_score: float | None = None
    decided_at: str | None = None
    decided_by: str | None = None
    decision_reason: str | None = None
    deployed_at: str | None = None
    rolled_back_at: str | None = None
    row_id: int | None = None

    def __post_init__(self) -> None:
        _require_str(self.change_id, "change_id")
        _require_str(self.title, "title")
        _require_str(self.description, "description")
        _require_str(self.requested_by, "requested_by")
        if not isinstance(self.status, ChangeStatus):
            raise ValueError(
                f"ChangeRequest: status muss ChangeStatus sein, "
                f"nicht {type(self.status).__name__}"
            )
        if not isinstance(self.type, ChangeType):
            raise ValueError(
                f"ChangeRequest: type muss ChangeType sein, "
                f"nicht {type(self.type).__name__}"
            )
        require_utc_iso(self.timestamp, "timestamp")
        require_utc_iso(self.created_at, "created_at")
        _require_opt_utc_iso(self.decided_at, "decided_at")
        _require_opt_utc_iso(self.deployed_at, "deployed_at")
        _require_opt_utc_iso(self.rolled_back_at, "rolled_back_at")
        if self.files_affected is not None:
            if not isinstance(self.files_affected, list):
                raise ValueError(
                    "ChangeRequest: files_affected muss list[str] sein"
                )
            for f in self.files_affected:
                if not isinstance(f, str):
                    raise ValueError(
                        "ChangeRequest: files_affected enthaelt "
                        "Nicht-String"
                    )
        if self.risk_score is not None:
            if not isinstance(self.risk_score, (int, float)):
                raise ValueError(
                    "ChangeRequest: risk_score muss Zahl sein"
                )

    # ------------------------------------------------------------------ #
    # Serialisierung
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Repraesentation fuer Audit, JSON-Export, CLI."""
        return {
            "id": self.row_id,
            "change_id": self.change_id,
            "timestamp": self.timestamp,
            "title": self.title,
            "description": self.description,
            "requested_by": self.requested_by,
            "status": self.status.value,
            "type": self.type.value,
            "diff_or_patch": self.diff_or_patch,
            "files_affected": list(self.files_affected)
                if self.files_affected is not None else None,
            "rollback_plan": self.rollback_plan,
            "test_plan": self.test_plan,
            "related_approval_id": self.related_approval_id,
            "related_event_id": self.related_event_id,
            "risk_category": self.risk_category,
            "risk_score": self.risk_score,
            "decided_at": self.decided_at,
            "decided_by": self.decided_by,
            "decision_reason": self.decision_reason,
            "deployed_at": self.deployed_at,
            "rolled_back_at": self.rolled_back_at,
            "created_at": self.created_at,
        }

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "ChangeRequest":
        """Baut einen ChangeRequest aus einer sqlite3.Row / Mapping."""
        files_raw = row["files_affected"]
        files: list[str] | None
        if files_raw is None or files_raw == "":
            files = None
        else:
            try:
                parsed = json.loads(files_raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"ChangeRequest: files_affected nicht parsebar: "
                    f"{files_raw!r}"
                ) from exc
            if not isinstance(parsed, list):
                raise ValueError(
                    "ChangeRequest: files_affected muss JSON-Array sein"
                )
            files = [str(x) for x in parsed]

        return cls(
            row_id=row["id"],
            change_id=row["change_id"],
            timestamp=row["timestamp"],
            title=row["title"],
            description=row["description"],
            requested_by=row["requested_by"],
            status=ChangeStatus(row["status"]),
            type=ChangeType(row["type"]),
            diff_or_patch=row["diff_or_patch"],
            files_affected=files,
            rollback_plan=row["rollback_plan"],
            test_plan=row["test_plan"],
            related_approval_id=row["related_approval_id"],
            related_event_id=row["related_event_id"],
            risk_category=row["risk_category"],
            risk_score=row["risk_score"],
            decided_at=row["decided_at"],
            decided_by=row["decided_by"],
            decision_reason=row["decision_reason"],
            deployed_at=row["deployed_at"],
            rolled_back_at=row["rolled_back_at"],
            created_at=row["created_at"],
        )


__all__ = [
    "ChangeStatus",
    "ChangeType",
    "ChangeRequest",
    "utc_now_iso",
    "require_utc_iso",
]
