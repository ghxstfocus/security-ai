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
from core.config import get_model_default, get_model_large
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


# Zustandsfragen: beziehen sich auf konkrete Zeitpunkte, Ereignisse,
# Geraete. Werden ohne Kontext ehrlich abgelehnt (no_context-Pfad).
_STATE_QUESTION_RE = re.compile(
    r"\b(heute|gestern|vorgestern|letzte[sn]?|"
    r"diese[sn]?|"
    r"passiert\w*|vorgefallen\w*|aufgefallen\w*|"
    r"auff(?:a|ae|\u00e4)llig\w*|"
    r"verd(?:ae|a|\u00e4)chtig\w*|"
    r"anomal\w*|"
    r"online|offline|aktiv|inaktiv|"
    r"neu|unbekannt|"
    r"welche\s+(ip|geraet|host|person)|"
    r"wie\s+viele|wieviele|"
    r"seit\s+wann|"
    r"wer\s+(war|hat|ist)|"
    r"wo\s+(war|ist)|"
    r"wann\s+(war|hat)|"
    r"status|zustand|"
    r"zeig\s+mir|"
    r"liste\s+(alle|mir))\b",
    re.IGNORECASE,
)


def _is_state_question(question: str) -> bool:
    if not isinstance(question, str):
        return False
    return _STATE_QUESTION_RE.search(question) is not None


# Kritische Kategorien: bei Zustandsfrage mit diesen Werten
# schaltet der Service auf das grosse Modell um.
_CRITICAL_CATEGORIES = frozenset({"CONFIRMED", "SECURITY_ALERT"})

# Modellabhaengige Timeouts (Sekunden). Fallback 60.
_MODEL_TIMEOUTS = {
    "llama3.2:3b": 30,
    "qwen2.5:7b": 180,
}


def _timeout_for_model(model: str) -> int:
    if not isinstance(model, str) or not model:
        return 60
    return _MODEL_TIMEOUTS.get(model, 60)


def _has_critical_assessments(context: ContextBundle) -> bool:
    for ra in context.risk_assessments:
        cat = _get_field(ra, "category")
        if isinstance(cat, str) and cat in _CRITICAL_CATEGORIES:
            return True
    return False


def _is_critical_state_question(
    question: str, context: ContextBundle,
) -> bool:
    return _is_state_question(question) and _has_critical_assessments(
        context
    )


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
    used_llm: bool = False
    llm_error: str | None = None
    answer_id: str | None = None
    created_at: datetime | None = None
    # Phase 3.5 Erweiterungen
    source: str = "llm"
    # Werte: "llm" | "detail_append" | "no_context" | "llm_error"
    model: str | None = None
    model_reason: str | None = None
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
        large_model: str | None = None,
        auto_large: bool = True,
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
        self._large_model = (
            large_model if large_model is not None
            else get_model_large()
        )
        self._auto_large = bool(auto_large)

    # ------------------------------------------------------------------ #
    # Modellwahl
    # ------------------------------------------------------------------ #

    def _select_model(
        self,
        question: str,
        context: ContextBundle,
        explicit_model: str | None,
    ) -> tuple[str, str, int]:
        """
        Liefert (model, reason, timeout).

        Prioritaet:
        1. explicit_model (CLI --model)
        2. large_model, wenn auto_large und kritische Zustandsfrage
        3. default_model
        """
        if explicit_model:
            return (
                explicit_model,
                "explicit_user",
                _timeout_for_model(explicit_model),
            )
        if self._auto_large and _is_critical_state_question(
            question, context
        ):
            return (
                self._large_model,
                "auto_critical_state",
                _timeout_for_model(self._large_model),
            )
        return (
            self._default_model,
            "default",
            _timeout_for_model(self._default_model),
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
        on_model_selected: Any | None = None,
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

        # 4b) no_context-Pfad: Zustandsfrage ohne Kontext -> ehrlich
        if _is_state_question(question) and context.is_empty():
            self._log(
                "chat_answered",
                principal=principal_name,
                source="no_context",
                context_counts=context.counts(),
                context_redacted=context.redacted,
            )
            return ChatResponse(
                answer=(
                    "Ich habe aktuell keine Daten zu dieser Frage. "
                    "Der Kontext ist leer."
                ),
                principal=principal_name,
                question=question,
                context_used=context,
                used_llm=False,
                source="no_context",
                model=None,
            )

        # 5) Normaler LLM-Pfad
        effective_model, model_reason, model_timeout = (
            self._select_model(question, context, model)
        )

        # Callback, BEVOR das LLM startet (Warnung an den Nutzer)
        if on_model_selected is not None:
            try:
                on_model_selected(effective_model, model_reason)
            except Exception as exc:
                # Callback-Fehler nicht propagieren; Audit
                self._log(
                    "chat_model_callback_failed",
                    error=str(exc),
                )

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
            timeout=timeout if timeout is not None else float(model_timeout),
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
            model_reason=model_reason,
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
            model_reason=model_reason,
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

# ---------------------------------------------------------------------- #
# Aggregation fuer den Prompt
# ---------------------------------------------------------------------- #

def _get_field(obj, name, default=None):
    """Liest aus dict oder Objekt. Beide Typen unterstuetzt."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _ra_field(ra, name, default=None):
    """Liest Feld aus einem risk_assessment-Eintrag.

    Unterstuetzt zwei Formen:
    - dict (aus core/reporting/audit_reader.read_risk_assessments)
    - Objekt mit Attributen (z. B. RiskAssessment)
    """
    return _get_field(ra, name, default)


def _format_categories(entries) -> str:
    counts: dict[str, int] = {}
    for e in entries:
        cat = _ra_field(e, "category")
        if not isinstance(cat, str) or not cat:
            cat = "UNKNOWN"
        counts[cat] = counts.get(cat, 0) + 1
    if not counts:
        return ""
    return ", ".join(
        f"{k}={v}" for k, v in sorted(counts.items())
    )


def _format_rules(entries) -> str:
    counts: dict[str, int] = {}
    for e in entries:
        r = _ra_field(e, "rule_id")
        if not isinstance(r, str) or not r:
            continue
        counts[r] = counts.get(r, 0) + 1
    if not counts:
        return ""
    return ", ".join(
        f"{k}={v}" for k, v in sorted(counts.items())
    )


def _format_time_range(entries) -> str:
    ts = [
        _ra_field(e, "timestamp")
        for e in entries
        if isinstance(_ra_field(e, "timestamp"), str)
    ]
    if not ts:
        return ""
    return f"{min(ts)} .. {max(ts)}"


def _format_top_scores(entries, limit: int = 5) -> str:
    scores = []
    for e in entries:
        s = _ra_field(e, "score")
        if isinstance(s, (int, float)):
            scores.append(float(s))
    if not scores:
        return ""
    top = sorted(scores, reverse=True)[:limit]
    return ", ".join(f"{s:.2f}" for s in top)


_DEFAULT_SYSTEM_PROMPT = (
    "Du bist eine Security-KI fuer ein "
    "Homelab-Sicherheitssystem.\n"
    "\n"
    "Du kannst zwei Arten von Fragen beantworten:\n"
    "\n"
    "1. Konzeptfragen (\"Was ist ein Portscan?\", "
    "\"Was bedeutet RBAC?\"): Beantworte sie aus deinem "
    "Wissen. Kurz und praezise.\n"
    "\n"
    "2. Zustandsfragen (\"Was ist heute Nacht passiert?\", "
    "\"Welche Geraete sind online?\"): Beantworte sie "
    "NUR auf Basis des mitgelieferten Kontexts. Wenn der "
    "Kontext keine Antwort enthaelt, sage das ehrlich. "
    "Spekuliere nicht. Erfinde keine Zahlen, Zeiten, IPs "
    "oder Ereignisse.\n"
    "Bei Zustandsfragen mit CONFIRMED- oder "
    "SECURITY_ALERT-Assessments ist die Antwort JA "
    "(es gab Auffaelligkeiten). Verweise auf die Zahlen.\n"
    "\n"
    "Du entscheidest nicht. Du erklaerst.\n"
    "Du empfiehlst keine Aktionen ohne Freigabe.\n"
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

    # Harter Hinweis bei kritischen Assessments
    if _has_critical_assessments(context):
        cats = _format_categories(context.risk_assessments)
        lines.append(
            f"WICHTIG: Der Kontext enthaelt kritische "
            f"Risk-Assessments ({cats}). Bei Fragen nach "
            f"Auffaelligkeiten ist die Antwort JA."
        )

    lines.append("Kontext:")
    counts = context.counts()
    for k, v in counts.items():
        lines.append(f"- {k}: {v}")

    # Risk-Assessments aufschluesseln
    ra = context.risk_assessments
    if ra:
        cats = _format_categories(ra)
        if cats:
            lines.append(f"- risk_assessments.categories: {cats}")
            lines.append(
                "  (CONFIRMED = bestaetigter Vorfall, "
                "SECURITY_ALERT = Sicherheitsalarm, "
                "SUSPICION = Verdacht, ANOMALY = Anomalie, "
                "EVENT = normales Ereignis)"
            )
        rules = _format_rules(ra)
        if rules:
            lines.append(f"- risk_assessments.rules: {rules}")
        tr = _format_time_range(ra)
        if tr:
            lines.append(f"- risk_assessments.time_range: {tr}")
        top = _format_top_scores(ra, limit=5)
        if top:
            lines.append(f"- risk_assessments.top_scores: {top}")

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
