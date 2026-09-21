"""
Datenmodelle fuer den Kontext-Bauer.

ContextBundle ist das Ergebnis eines Bau-Vorgangs: alles, was
das lokale LLM sehen darf. Es ist bewusst eine flache, frozen
Dataclass, damit Tests und Audit einfach sind.

Wichtig:
- ContextBundle enthaelt NUR gefilterte Rohdaten.
- redacted=True, sobald mindestens eine Redaktion stattfand.
- built_at ist UTC-aware.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_utc(dt: datetime, field_name: str) -> None:
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(
            f"ContextBundle: {field_name} muss timezone-aware sein"
        )


# ---------------------------------------------------------------------- #
# LogExcerpt
# ---------------------------------------------------------------------- #

@dataclass(frozen=True)
class LogExcerpt:
    """
    Ein einzelner Log-Ausschnitt.

    path ist der Pfad, aus dem der Ausschnitt stammt.
    line_count ist die Anzahl der Zeilen im Ausschnitt.
    text ist bereits redigiert.
    """

    path: str
    text: str
    line_count: int
    redacted: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path:
            raise ValueError("LogExcerpt: path darf nicht leer sein")
        if not isinstance(self.text, str):
            raise ValueError("LogExcerpt: text muss String sein")
        if not isinstance(self.line_count, int) or self.line_count < 0:
            raise ValueError(
                "LogExcerpt: line_count muss int >= 0 sein"
            )


# ---------------------------------------------------------------------- #
# ContextBundle
# ---------------------------------------------------------------------- #

@dataclass(frozen=True)
class ContextBundle:
    """
    Alles, was das LLM sehen darf.

    Felder sind absichtlich breit typisiert (Event | None,
    tuple[Any, ...]), um Zirkelimporte zu vermeiden. Die
    konkreten Typen sind: Event (core.events.event),
    RiskAssessment (core.risk.models), ApprovalRequest
    (core.approval.models), ChangeRequest (core.changes.models).
    """

    built_at: datetime
    event: Any | None = None
    recent_events: tuple[Any, ...] = field(default_factory=tuple)
    inventory_snapshot: dict[str, Any] = field(default_factory=dict)
    risk_assessments: tuple[Any, ...] = field(default_factory=tuple)
    open_approvals: tuple[Any, ...] = field(default_factory=tuple)
    open_changes: tuple[Any, ...] = field(default_factory=tuple)
    log_excerpts: tuple[LogExcerpt, ...] = field(default_factory=tuple)
    redacted: bool = False
    notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _require_utc(self.built_at, "built_at")
        if not isinstance(self.inventory_snapshot, dict):
            raise ValueError(
                "ContextBundle: inventory_snapshot muss dict sein"
            )
        if not isinstance(self.redacted, bool):
            raise ValueError(
                "ContextBundle: redacted muss bool sein"
            )
        for name, value in (
            ("recent_events", self.recent_events),
            ("risk_assessments", self.risk_assessments),
            ("open_approvals", self.open_approvals),
            ("open_changes", self.open_changes),
            ("log_excerpts", self.log_excerpts),
            ("notes", self.notes),
        ):
            if not isinstance(value, tuple):
                raise ValueError(
                    f"ContextBundle: {name} muss tuple sein"
                )

    # ------------------------------------------------------------------ #
    # Hilfsmethoden
    # ------------------------------------------------------------------ #

    def is_empty(self) -> bool:
        """True, wenn ausser built_at nichts befuellt ist."""
        return (
            self.event is None
            and not self.recent_events
            and not self.inventory_snapshot
            and not self.risk_assessments
            and not self.open_approvals
            and not self.open_changes
            and not self.log_excerpts
        )

    def counts(self) -> dict[str, int]:
        """Anzahl Eintraege pro Kategorie. Nuetzlich fuer Audit."""
        return {
            "recent_events": len(self.recent_events),
            "inventory_snapshot": len(self.inventory_snapshot),
            "risk_assessments": len(self.risk_assessments),
            "open_approvals": len(self.open_approvals),
            "open_changes": len(self.open_changes),
            "log_excerpts": len(self.log_excerpts),
        }


__all__ = [
    "ContextBundle",
    "LogExcerpt",
    "utc_now",
]


def utc_now() -> datetime:
    """Oeffentlicher Helfer fuer Tests und Builder."""
    return _utc_now()
