"""
Modell-Interface und Dummy-Implementierung.

Das echte Modell (lokales LLM oder Cloud-API) wird später
implementiert. Für Tests und Phase 1 reicht das DummyModel.

Wichtig:
- Das Modell trifft KEINE Ausführungsentscheidungen.
- Es erzeugt Pläne.
- Der Loop prüft und führt aus.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from collections.abc import Callable

from core.events.event import Event
from harness.agent_loop.loop import Plan, PlanStep


class BaseModel:
    """
    Basisklasse für Modelle.

    Unterklassen implementieren plan().
    """

    def plan(self, event: Event, context: dict[str, Any]) -> Plan:
        raise NotImplementedError


@dataclass
class DummyModel(BaseModel):
    """
    Deterministisches Modell für Tests.

    Erzeugt einen festen Plan, unabhängig vom Event.
    """
    fixed_steps: list[PlanStep] = field(default_factory=list)
    summary: str = "dummy plan"

    def plan(self, event: Event, context: dict[str, Any]) -> Plan:
        return Plan(
            steps=list(self.fixed_steps),
            summary=self.summary,
        )


@dataclass
class RuleModel(BaseModel):
    """
    Regelbasiertes Modell.

    Erlaubt, für bestimmte event_types einen Plan zu hinterlegen.
    Fallback: leerer Plan.
    """
    rules: dict[str, list[PlanStep]] = field(default_factory=dict)

    def plan(self, event: Event, context: dict[str, Any]) -> Plan:
        steps = self.rules.get(event.event_type, [])
        return Plan(
            steps=list(steps),
            summary=f"rule-based plan for {event.event_type}",
        )


@dataclass
class CallableModel(BaseModel):
    """
    Modell, das eine Funktion aufruft.

    Nützlich für Tests, bei denen der Plan dynamisch entstehen soll.
    """
    planner: Callable[[Event, dict[str, Any]], Plan]

    def plan(self, event: Event, context: dict[str, Any]) -> Plan:
        return self.planner(event, context)


__all__ = [
    "BaseModel",
    "CallableModel",
    "DummyModel",
    "RuleModel",
]
