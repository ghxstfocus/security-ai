"""
Datenmodelle fuer den Kontext-Bauer.

ContextBundle ist das Ergebnis eines Bau-Vorgangs: alles, was
das lokale LLM sehen darf. Es ist bewusst eine flache, frozen
Dataclass, damit Tests und Audit einfach sind.

Wichtig:
- ContextBundle enthaelt NUR gefilterte Rohdaten.
- redacted=True, sobald mindestens eine Redaktion stattfand.
- built_at ist UTC-aware.
- Kein Zirkelimport zur Laufzeit: die konkreten Event-,
  Risk-, Approval- und Change-Typen werden nur unter
  TYPE_CHECKING importiert (PEP 563).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.approval.models import ApprovalRequest
    from core.changes.models import ChangeRequest
    from core.events.event import Event
    from core.risk.models import RiskAssessment


def _require_utc(dt: datetime, field_name: str) -> None:
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(
            f"ContextBundle: {field_name} muss timezone-aware sein"
        )


def utc_now() -> datetime:
    """Aktueller UTC-Zeitstempel. Helfer fuer Builder und Tests."""
    return datetime.now(UTC)


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
    redacted zeigt an, ob in diesem Ausschnitt redigiert wurde.
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
        if not isinstance(self.redacted, bool):
            raise ValueError("LogExcerpt: redacted muss bool sein")


# ---------------------------------------------------------------------- #
# ContextBundle
# ---------------------------------------------------------------------- #

@dataclass(frozen=True)
class ContextBundle:
    """
    Alles, was das LLM sehen darf.

    Struktur inventory_snapshot:
        {
            "device_count": int,
            "whitelist_count": int,
            "devices_online": int,
            "devices_offline": int,
            "recently_added": list[str],
            "recently_offline": list[str],
        }
    Aggregate, keine Rohdaten. Kein PII.

    Semantik:
    - is_empty(): True nur, wenn ALLE Sammlungen leer sind UND
      event is None UND inventory_snapshot leer ist.
    - counts(): Anzahl pro Sammlung. event wird NICHT gezaehlt
      (event ist None oder genau 1).
    """

    built_at: datetime
    # Zeitraum des Kontexts in Stunden (Auflage 837, Punkt 31).
    # Bestimmt den Anzeige-Text in _answer_fact
    # ("in den letzten N Stunden/Tagen"). Default 24.
    since_hours: int = 24
    event: Event | None = None
    recent_events: tuple[Event, ...] = field(default_factory=tuple)
    inventory_snapshot: dict[str, Any] = field(default_factory=dict)
    risk_assessments: tuple[RiskAssessment, ...] = field(
        default_factory=tuple
    )
    open_approvals: tuple[ApprovalRequest, ...] = field(
        default_factory=tuple
    )
    open_changes: tuple[ChangeRequest, ...] = field(
        default_factory=tuple
    )
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

    def has_data(self) -> bool:
        """
        Kehrwert von is_empty(): True, wenn irgendein Feld
        befuellt ist.
        """
        return not self.is_empty()

    def is_empty(self) -> bool:
        """
        True, wenn ausser built_at nichts befuellt ist.

        Heisst: event is None UND alle Sammlungen leer UND
        inventory_snapshot leer.
        """
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
        """
        Anzahl Eintraege pro Kategorie. Nuetzlich fuer Audit.

        event wird nicht gezaehlt (None oder 1).
        """
        return {
            "events": len(self.recent_events),
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
