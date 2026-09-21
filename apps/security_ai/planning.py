"""
Deterministisches Planungsmodell fuer die Security AI.

Erzeugt aus einem Event (mit angereichertem risk_category)
einen Plan. Kein LLM, keine Heuristik — feste Regeln.

Wird vom AgentLoop ueber model.plan(event, context) aufgerufen.

Regeln:
  risk_category in {SECURITY_ALERT, CONFIRMED}:
    - kind == "brute_force"  -> telegram_alert CRITICAL
    - kind == "network_scan" -> telegram_alert CRITICAL
    - sonst                  -> telegram_alert WARNING
  sonst:
    - kein Plan
"""
from __future__ import annotations

from typing import Any

from core.events.event import Event
from harness.agent_loop.loop import Plan, PlanStep
from harness.agent_loop.model import BaseModel


_ALERT_CATEGORIES = frozenset({"SECURITY_ALERT", "CONFIRMED"})

_CATEGORY_TO_SEVERITY = {
    "EVENT": "INFO",
    "ANOMALY": "INFO",
    "SUSPICION": "WARNING",
    "SECURITY_ALERT": "WARNING",
    "CONFIRMED": "CRITICAL",
}

_CRITICAL_KINDS = frozenset({"brute_force", "network_scan"})


class SecurityPlanModel(BaseModel):
    """
    Regelbasiertes Planungsmodell.

    Liest event.data["risk_category"] und event.event_type, baut
    daraus 0..1 PlanStep(s) fuer telegram_alert.
    """

    def plan(self, event: Event, context: dict[str, Any]) -> Plan:
        category = event.data.get("risk_category")
        if category not in _ALERT_CATEGORIES:
            return Plan(steps=[], summary="kein Alarm")

        severity = _category_to_severity(category, event)
        title = _build_title(event)
        message = _build_message(event)

        step = PlanStep(
            tool="telegram_alert",
            args={
                "title": title,
                "message": message,
                "severity": severity,
            },
            reason=(
                f"risk_category={category} "
                f"score={event.data.get('risk_score')}"
            ),
        )
        return Plan(steps=[step], summary=f"alert {severity}: {title}")


# ---------------------------------------------------------------------- #
# Helpers
# ---------------------------------------------------------------------- #

def _category_to_severity(category: str, event: Event) -> str:
    """Liefert die telegram-severity aus der Risk-Category."""
    sev = _CATEGORY_TO_SEVERITY.get(category, "WARNING")
    kind = event.data.get("kind")
    if kind in _CRITICAL_KINDS:
        return "CRITICAL"
    return sev


def _build_title(event: Event) -> str:
    """Baut einen kurzen, stabilen Titel aus dem Event."""
    et = event.event_type
    if et == "unknown_device":
        ident = event.data.get("identifier") or "?"
        return f"Unbekanntes Geraet: {ident}"
    if et == "port_scan":
        src = event.data.get("src_ip") or "?"
        kind = event.data.get("kind") or "scan"
        return f"{kind} von {src}"
    return f"Ereignis: {et}"


def _build_message(event: Event) -> str:
    """Baut den Nachrichtentext aus den wichtigsten Feldern."""
    lines = [f"event_type: {event.event_type}"]
    if event.data.get("identifier"):
        lines.append(f"identifier: {event.data['identifier']}")
    if event.data.get("entity_name"):
        lines.append(f"entity_name: {event.data['entity_name']}")
    if event.data.get("network_type"):
        lines.append(f"network_type: {event.data['network_type']}")
    if event.data.get("src_ip"):
        lines.append(f"src_ip: {event.data['src_ip']}")
    if event.data.get("dst_ip"):
        lines.append(f"dst_ip: {event.data['dst_ip']}")
    if event.data.get("kind"):
        lines.append(f"kind: {event.data['kind']}")
    if event.data.get("risk_category"):
        lines.append(f"risk_category: {event.data['risk_category']}")
    if event.data.get("risk_score") is not None:
        lines.append(f"risk_score: {event.data['risk_score']}")
    return "\n".join(lines)


__all__ = [
    "SecurityPlanModel",
]
