"""
ChatService: Service-Schicht fuer Chat mit der lokalen KI.

Verantwortung:
- Berechtigung pruefen (chat.ask, optional chat.include_details).
- Kontext bauen (ContextBuilder).
- LLM aufrufen (LLMClientProtocol).
- Audit schreiben.

Design:
- Kein UI-Code. CLI (scripts/chat_cli.py) und spaeteres
  Web-Dashboard rufen denselben Service.
- DB ist Wahrheit, LLM ist nachgelagert.
- LLM entscheidet nichts. Der Service ruft nur das LLM, um
  eine Antwort zu formulieren.
- Fail closed bei RBAC, fail open bei LLM-Fehler (Antwort
  mit Fehlertext, kein Absturz).
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from core.access.checker import AccessChecker, AccessDeniedError
from harness.audit.writer import AuditWriter
from harness.context.builder import ContextBuilder
from harness.context.models import ContextBundle


AGENT = "security_ai"
TOOL = "chat_service"


# ---------------------------------------------------------------------- #
# LLM-Client-Protokoll
# ---------------------------------------------------------------------- #

class LLMClientProtocol(Protocol):
    """
    Minimale Schnittstelle fuer einen LLM-Client.

    Echte Implementierung: harness.llm.OllamaClient (spaeter).
    Test-Implementierung: ein Fake, der eine feste Antwort liefert.
    """

    def generate(
        self,
        *,
        prompt: str,
        system: str | None = None,
        max_tokens: int | None = None,
        timeout: float | None = None,
    ) -> str:
        ...


# ---------------------------------------------------------------------- #
# Ergebnis-Typen
# ---------------------------------------------------------------------- #

class ChatServiceError(RuntimeError):
    """Fachlicher Fehler im ChatService."""


@dataclass(frozen=True)
class ChatResponse:
    """Antwort auf eine Chat-Frage."""

    answer: str
    principal: str
    question: str
    context_used: ContextBundle
    used_llm: bool
    llm_error: str | None = None
    answer_id: str | None = None
    created_at: datetime | None = None


# ---------------------------------------------------------------------- #
# ChatService
# ---------------------------------------------------------------------- #

class ChatService:
    def __init__(
        self,
        conn: sqlite3.Connection,
        audit_writer: AuditWriter,
        llm_client: LLMClientProtocol,
        *,
        context_builder: ContextBuilder | None = None,
        system_prompt: str | None = None,
    ) -> None:
        if audit_writer is None:
            raise ChatServiceError(
                "audit_writer ist Pflicht (fail closed)"
            )
        if llm_client is None:
            raise ChatServiceError(
                "llm_client ist Pflicht (fail closed)"
            )
        self._conn = conn
        self._audit = audit_writer
        self._llm = llm_client
        self._builder = context_builder or ContextBuilder()
        self._system_prompt = system_prompt or _DEFAULT_SYSTEM_PROMPT
        self._checker = AccessChecker(conn)

    # ------------------------------------------------------------------ #
    # Audit
    # ------------------------------------------------------------------ #

    def _log(self, kind: str, **extra: Any) -> None:
        if "kind" in extra:
            raise ChatServiceError(
                "details.kind darf nicht als extra uebergeben werden"
            )
        details: dict[str, Any] = {"kind": kind}
        details.update(extra)
        self._audit.log(
            agent=AGENT,
            tool=TOOL,
            policy_result="ALLOWED",
            permission_level=0,
            execution_status="OK",
            details=details,
        )

    # ------------------------------------------------------------------ #
    # ask
    # ------------------------------------------------------------------ #

    def ask(
        self,
        principal_name: str,
        question: str,
        *,
        include_details: bool = False,
        event: Any | None = None,
        recent_events: Any = (),
        inventory_snapshot: dict[str, Any] | None = None,
        risk_assessments: Any = (),
        open_approvals: Any = (),
        open_changes: Any = (),
        log_excerpts: Any = (),
        max_tokens: int | None = None,
        timeout: float | None = None,
    ) -> ChatResponse:
        """
        Beantwortet eine Frage.

        Ablauf:
        1. RBAC: chat.ask Pflicht. include_details: zusaetzlich
           chat.include_details Pflicht.
        2. Kontext bauen.
        3. Prompt bauen.
        4. LLM aufrufen.
        5. Audit.
        """
        # 1) RBAC
        self._checker.require_permission(principal_name, "chat.ask")
        if include_details:
            self._checker.require_permission(
                principal_name, "chat.include_details"
            )

        # 2) Kontext
        context = self._builder.build(
            event=event,
            recent_events=recent_events,
            inventory_snapshot=inventory_snapshot,
            risk_assessments=risk_assessments,
            open_approvals=open_approvals,
            open_changes=open_changes,
            log_excerpts=log_excerpts,
        )

        # 3) Prompt
        prompt = _build_prompt(
            question=question,
            context=context,
            include_details=include_details,
        )

        # 4) LLM (fail open)
        try:
            answer = self._llm.generate(
                prompt=prompt,
                system=self._system_prompt,
                max_tokens=max_tokens,
                timeout=timeout,
            )
            used_llm = True
            llm_error = None
        except Exception as exc:
            answer = (
                "Die lokale KI ist momentan nicht erreichbar. "
                "Die Frage wurde nicht beantwortet."
            )
            used_llm = False
            llm_error = str(exc)

        # 5) Audit
        self._log(
            "chat_answered",
            principal=principal_name,
            question_len=len(question),
            include_details=include_details,
            used_llm=used_llm,
            context_counts=context.counts(),
            context_redacted=context.redacted,
        )
        if llm_error is not None:
            self._log("chat_llm_error", error=llm_error)

        return ChatResponse(
            answer=answer,
            principal=principal_name,
            question=question,
            context_used=context,
            used_llm=used_llm,
            llm_error=llm_error,
        )


# ---------------------------------------------------------------------- #
# Prompt-Bau
# ---------------------------------------------------------------------- #

_DEFAULT_SYSTEM_PROMPT = (
    "Du bist die Security AI eines Homelab. Du erklaerst, du "
    "entscheidest nicht. Du fuehrst keine Tools aus. Du gibst "
    "keine Anweisungen an Systeme. Antworte auf Deutsch, kurz "
    "und sachlich."
)


def _build_prompt(
    *,
    question: str,
    context: ContextBundle,
    include_details: bool,
) -> str:
    """
    Baut den Prompt aus Frage und Kontext.

    Details (Rohdaten) werden nur eingefuegt, wenn include_details
    True ist. Sonst nur aggregierte Zaehler.
    """
    lines: list[str] = []
    lines.append("Kontext:")
    counts = context.counts()
    for k, v in counts.items():
        lines.append(f"- {k}: {v}")
    if context.redacted:
        lines.append("- Hinweis: Kontext wurde redigiert.")
    if context.inventory_snapshot:
        for k, v in context.inventory_snapshot.items():
            lines.append(f"- inventory.{k}: {v}")

    if include_details:
        if context.event is not None:
            lines.append(f"event_id: {getattr(context.event, 'event_id', '?')}")
        if context.log_excerpts:
            for i, log in enumerate(context.log_excerpts):
                lines.append(f"log[{i}] {log.path}: {log.text}")

    lines.append("")
    lines.append("Frage:")
    lines.append(question)
    return "\n".join(lines)


__all__ = [
    "ChatService",
    "ChatServiceError",
    "ChatResponse",
    "LLMClientProtocol",
]
