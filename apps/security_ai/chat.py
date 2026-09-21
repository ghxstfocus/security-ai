"""
ChatService: Service-Schicht fuer Chat mit der lokalen KI.

Verantwortung:
- Berechtigung pruefen (chat.ask, optional chat.detail,
  chat.include_details).
- Kontext bauen (ContextBuilder).
- LLM aufrufen (LLMClientProtocol).
- Audit schreiben.

Design:
- Kein UI-Code. CLI (scripts/chat_cli.py) und spaeteres
  Web-Dashboard rufen denselben Service.
- DB ist Wahrheit, LLM ist nachgelagert.
- LLM entscheidet nichts.
- Fail closed bei RBAC UND bei LLM-Fehler (LLMError wird
  propagiert). Ein Chat, der eine erfundene Antwort liefert,
  ist schlimmer als einer, der "nicht erreichbar" sagt.

Audit-Kinds:
- chat_query          (immer, vor RBAC)
- chat_access_denied  (bei RBAC-Verweigerung: chat.ask,
                       chat.include_details, chat.detail)
- chat_answered       (bei erfolgreicher Antwort)
- chat_llm_error      (bei LLM-Fehler)
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from core.access.checker import AccessChecker, AccessDeniedError
from core.config import get_model_default
from harness.audit.writer import AuditWriter
from harness.context.builder import ContextBuilder
from harness.context.models import ContextBundle
from harness.llm.errors import LLMError
from harness.llm.models import LLMRequest


AGENT = "security_ai"
TOOL = "chat_service"


# ---------------------------------------------------------------------- #
# LLM-Client-Protokoll
# ---------------------------------------------------------------------- #

class LLMClientProtocol(Protocol):
    """
    Minimale Schnittstelle fuer einen LLM-Client.

    Echte Implementierung: harness.llm.client.OllamaClient.
    Test-Implementierung: ein Fake, der eine feste Antwort liefert.
    """

    def generate(self, request: LLMRequest):  # pragma: no cover
        ...


# ---------------------------------------------------------------------- #
# Detail-Regex
# ---------------------------------------------------------------------- #

_DETAIL_RE = re.compile(
    r"\bwelche\s+ip\b|\bwhich\s+ip\b|\bip[- ]?adresse\b",
    re.IGNORECASE,
)


def _matches_detail_regex(question: str) -> bool:
    if not isinstance(question, str):
        return False
    return _DETAIL_RE.search(question) is not None


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
    # Phase 3.5 Erweiterungen
    source: str = "llm"      # "llm" | "detail_append"
    model: str | None = None
    denied: bool = False


# ---------------------------------------------------------------------- #
# ChatService
# ---------------------------------------------------------------------- #

class ChatService:
    def __init__(
        self,
        audit_writer: AuditWriter,
        llm_client: LLMClientProtocol,
        checker: AccessChecker,
        *,
        context_builder: ContextBuilder | None = None,
        system_prompt: str | None = None,
        default_model: str | None = None,
    ) -> None:
        if audit_writer is None:
            raise ChatServiceError(
                "audit_writer ist Pflicht (fail closed)"
            )
        if llm_client is None:
            raise ChatServiceError(
                "llm_client ist Pflicht (fail closed)"
            )
        if checker is None:
            raise ChatServiceError(
                "checker ist Pflicht (fail closed)"
            )
        self._audit = audit_writer
        self._llm = llm_client
        self._checker = checker
        self._builder = context_builder or ContextBuilder()
        self._system_prompt = system_prompt or _DEFAULT_SYSTEM_PROMPT
        self._default_model = (
            default_model if default_model is not None
            else get_model_default()
        )

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
    # interne Helfer
    # ------------------------------------------------------------------ #

    # ------------------------------------------------------------------ #
    # ask
    # ------------------------------------------------------------------ #

    def ask(
        self,
        principal_name: str,
        question: str,
        *,
        include_details: bool = False,
        detail: bool = False,
        model: str | None = None,
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
        1. chat_query (immer, vor RBAC)
        2. RBAC: chat.ask
        3. Detail-Pfad oder LLM-Pfad
        """
        if not isinstance(question, str) or not question.strip():
            raise ChatServiceError("Frage darf nicht leer sein")

        role = self._checker.role_of(principal_name)
        q_hash = hashlib.sha256(question.encode("utf-8")).hexdigest()
        q_hash_short = q_hash[:16]

        # 1) chat_query (immer, vor RBAC)
        self._log(
            "chat_query",
            principal=principal_name,
            role=role,
            question_hash=q_hash,
            question_hash_short=q_hash_short,
            detail_requested=bool(detail),
        )

        # 2) RBAC: chat.ask
        try:
            self._checker.require_permission(principal_name, "chat.ask")
        except AccessDeniedError:
            self._log(
                "chat_access_denied",
                principal=principal_name,
                reason="missing chat.ask",
            )
            raise

        # 3) Kontext bauen
        context = self._builder.build(
            event=event,
            recent_events=recent_events,
            inventory_snapshot=inventory_snapshot,
            risk_assessments=risk_assessments,
            open_approvals=open_approvals,
            open_changes=open_changes,
            log_excerpts=log_excerpts,
        )

        # 3b) RBAC: chat.include_details (nur wenn angefordert)
        if include_details:
            try:
                self._checker.require_permission(
                    principal_name, "chat.include_details"
                )
            except AccessDeniedError:
                self._log(
                    "chat_access_denied",
                    principal=principal_name,
                    reason="missing chat.include_details",
                )
                raise

        # 4) Detail-Pfad
        is_detail_question = detail or _matches_detail_regex(question)
        if is_detail_question:
            try:
                self._checker.require_permission(
                    principal_name, "chat.detail"
                )
            except AccessDeniedError:
                self._log(
                    "chat_access_denied",
                    principal=principal_name,
                    reason="missing chat.detail",
                )
                raise

            suffix = _build_detail_suffix(context)
            answer = f"Details:\n{suffix}"
            self._log(
                "chat_answered",
                principal=principal_name,
                source="detail_append",
                context_counts=context.counts(),
                context_redacted=context.redacted,
            )
            return ChatResponse(
                answer=answer,
                principal=principal_name,
                question=question,
                context_used=context,
                used_llm=False,
                source="detail_append",
                model=None,
            )

        # 5) Normaler LLM-Pfad
        effective_model = model if model is not None else self._default_model
        prompt = _build_prompt(
            question=question,
            context=context,
            include_details=include_details,
        )
        request = LLMRequest(
            prompt=prompt,
            system=self._system_prompt,
            model=effective_model,
            max_tokens=max_tokens if max_tokens is not None else 512,
            timeout=timeout if timeout is not None else 30.0,
        )

        try:
            response = self._llm.generate(request)
        except LLMError as exc:
            self._log(
                "chat_llm_error",
                principal=principal_name,
                error=str(exc),
            )
            raise

        text = getattr(response, "text", None)
        resp_model = getattr(response, "model", effective_model)
        if not isinstance(text, str):
            # Fail closed: ein Client, der kein LLMResponse liefert,
            # ist ein Programmierfehler.
            self._log(
                "chat_llm_error",
                principal=principal_name,
                error="LLM-Client lieferte kein text-Feld",
            )
            raise ChatServiceError(
                "LLM-Client lieferte kein text-Feld (LLMResponse.text)"
            )

        self._log(
            "chat_answered",
            principal=principal_name,
            source="llm",
            model=resp_model,
            include_details=include_details,
            context_counts=context.counts(),
            context_redacted=context.redacted,
        )
        return ChatResponse(
            answer=text,
            principal=principal_name,
            question=question,
            context_used=context,
            used_llm=True,
            source="llm",
            model=resp_model,
        )


# ---------------------------------------------------------------------- #
# Detail-Anhang
# ---------------------------------------------------------------------- #

def _build_detail_suffix(context: ContextBundle) -> str:
    """Baut die Detail-Zeilen aus Event + Inventory-Snapshot."""
    ips: set[str] = set()

    ev = context.event
    if ev is not None:
        data = getattr(ev, "data", None)
        if isinstance(data, dict):
            ident = data.get("identifier")
            if isinstance(ident, str) and ident:
                ips.add(ident)

    inv = context.inventory_snapshot or {}
    for key in ("recently_added", "recently_offline"):
        raw = inv.get(key)
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str) and item:
                    ips.add(item)

    if not ips:
        return "(keine Details verfuegbar)"
    return "\n".join(f"- {ip}" for ip in sorted(ips))


# ---------------------------------------------------------------------- #
# Prompt-Bau
# ---------------------------------------------------------------------- #

_DEFAULT_SYSTEM_PROMPT = (
    "Du bist die Security AI eines Homelab. "
    "Du erklaerst, du entscheidest nicht. "
    "Du fuehrst keine Tools aus. "
    "Du gibst keine Anweisungen an Systeme. "
    "Antworte NUR auf Basis des mitgelieferten Kontexts. "
    "Wenn der Kontext leer ist oder keine Antwort zulaesst, "
    "sage: 'Der Kontext enthaelt keine passenden Daten.' "
    "Spekuliere nicht. Erfinde keine Zahlen, Zeiten, IPs oder "
    "Ereignisse. "
    "Antworte auf Deutsch, kurz und sachlich."
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
            lines.append(
                f"event_id: {getattr(context.event, 'event_id', '?')}"
            )
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
