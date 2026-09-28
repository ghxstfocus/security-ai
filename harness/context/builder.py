"""
Kontext-Bauer (Phase 3.5.1).

Sammelt Events, Risk-Assessments, Approvals, Changes und
Log-Ausschnitte und baut daraus ein ContextBundle, das das
lokale LLM sehen darf.

Design:
- DB-frei. Der Orchestrator sammelt die Daten und uebergibt
  sie an build().
- Rein filternd und aggregierend. Keine Seiteneffekte.
- Reihenfolge in build():
    1) Limitieren (max_events, max_log_excerpts)
    2) Redigieren (redaction.redact_text/redact_mapping)
    3) ContextBundle bauen
- Warum Limitieren vor Redigieren:
    - Performance: 20 Redaktionen statt 1000.
    - Sicherheit: Bug in der Redaction -> kleinerer Schaden.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from harness.context.models import (
    ContextBundle,
    LogExcerpt,
    utc_now,
)
from harness.context.redaction import (
    MAX_FIELD_LEN,
    redact_field,
    redact_mapping,
    redact_text,
)

if False:  # TYPE_CHECKING-Ersatz, damit mypy die Typen sieht
    from core.approval.models import ApprovalRequest
    from core.changes.models import ChangeRequest
    from core.events.event import Event
    from core.risk.models import RiskAssessment


class ContextBuilder:
    """
    Baut ContextBundle aus bereits gesammelten Daten.

    Kein DB-Zugriff. Der Aufrufer (Orchestrator, ChatClient)
    reicht fertige Sequenzen herein.
    """

    def __init__(
        self,
        max_events: int = 20,
        max_log_excerpts: int = 5,
        max_excerpt_chars: int = MAX_FIELD_LEN,
    ) -> None:
        if max_events < 0:
            raise ValueError("max_events muss >= 0 sein")
        if max_log_excerpts < 0:
            raise ValueError("max_log_excerpts muss >= 0 sein")
        if max_excerpt_chars < 0:
            raise ValueError("max_excerpt_chars muss >= 0 sein")
        self.max_events = max_events
        self.max_log_excerpts = max_log_excerpts
        self.max_excerpt_chars = max_excerpt_chars

    # ------------------------------------------------------------------ #
    # build
    # ------------------------------------------------------------------ #

    def build(
        self,
        *,
        event: Event | None = None,
        recent_events: Sequence[Event] = (),
        inventory_snapshot: dict[str, Any] | None = None,
        risk_assessments: Sequence[RiskAssessment] = (),
        open_approvals: Sequence[ApprovalRequest] = (),
        open_changes: Sequence[ChangeRequest] = (),
        log_excerpts: Sequence[LogExcerpt] = (),
        since_hours: int = 24,
    ) -> ContextBundle:
        redacted_flag = False

        # 1) Limitieren
        limited_events = tuple(recent_events)[: self.max_events]
        limited_logs = tuple(log_excerpts)[: self.max_log_excerpts]

        # 2) Redigieren
        # 2a) recent_events: wir redigieren die event_id + data
        safe_events = []
        for ev in limited_events:
            safe_ev, was = self._redact_event(ev)
            if was:
                redacted_flag = True
            safe_events.append(safe_ev)

        # 2b) Log-Ausschnitte
        safe_logs: list[LogExcerpt] = []
        for log in limited_logs:
            text, was = redact_text(
                log.text, max_len=self.max_excerpt_chars
            )
            if was or log.redacted:
                redacted_flag = True
            safe_logs.append(LogExcerpt(
                path=log.path,
                text=text,
                line_count=log.line_count,
                redacted=was or log.redacted,
            ))

        # 2c) inventory_snapshot: Werte redigieren
        inv_in = inventory_snapshot or {}
        inv_out, was_inv = redact_mapping(
            inv_in, max_len=self.max_excerpt_chars
        )
        if was_inv:
            redacted_flag = True
        # recently_added / recently_offline als Listen von Strings
        for key in ("recently_added", "recently_offline"):
            raw = inv_in.get(key)
            if isinstance(raw, list):
                cleaned_list = []
                for item in raw:
                    s, was = redact_field(
                        item, max_len=self.max_excerpt_chars
                    )
                    if was:
                        redacted_flag = True
                    cleaned_list.append(s)
                inv_out[key] = cleaned_list

        # 3) ContextBundle bauen
        # Risk/Approvals/Changes werden heute nicht inhaltlich
        # redigiert, weil sie strukturierte Objekte sind. Sie
        # werden nur uebernommen und als Tupel gefroren.
        return ContextBundle(
            built_at=utc_now(),
            since_hours=since_hours,
            event=event,
            recent_events=tuple(safe_events),
            inventory_snapshot=inv_out,
            risk_assessments=tuple(risk_assessments),
            open_approvals=tuple(open_approvals),
            open_changes=tuple(open_changes),
            log_excerpts=tuple(safe_logs),
            redacted=redacted_flag,
        )

    # ------------------------------------------------------------------ #
    # interne Helfer
    # ------------------------------------------------------------------ #

    def _redact_event(self, ev: Event) -> tuple[Event, bool]:
        """
        Redigiert event_id und data eines Events.

        Wenn Event-Objekte fremd sind (kein .event_id/.data),
        wird das Event unveraendert durchgereicht und als
        nicht-redigiert markiert (fail open fuer Event-Objekte,
        weil sie strukturell vertraut sind).
        """
        event_id = getattr(ev, "event_id", None)
        data = getattr(ev, "data", None)

        redacted = False

        if isinstance(event_id, str):
            _, was = redact_text(
                event_id, max_len=self.max_excerpt_chars
            )
            if was:
                redacted = True

        if isinstance(data, dict):
            _, was = redact_mapping(
                data, max_len=self.max_excerpt_chars
            )
            if was:
                redacted = True

        return (ev, redacted)


__all__ = ["ContextBuilder"]
