"""
Agent Loop — sequenzieller Ablauf für jede Aktion.

Ablauf:

    INPUT -> CONTEXT -> MODEL -> PLAN -> POLICY CHECK
    -> TOOL SELECTION -> PERMISSION CHECK -> EXECUTION
    -> RESULT VALIDATION -> MODEL ANALYSIS -> DECISION
    -> ACTION / ALERT / APPROVAL -> AUDIT

Regeln:
- Kein Tool-Aufruf ohne Policy Check.
- Kein Tool-Aufruf ohne Permission Check.
- Jede Aktion wird auditiert.
- Bei Level 5: sofortiger Abbruch.
- Bei Level 4: Pause, warten auf Freigabe.
- Budget: max_iterations, max_runtime, max_tool_calls.

Verwendung (mit Dummy-Modell für Tests):

    from harness.agent_loop.loop import AgentLoop, LoopBudget
    from harness.agent_loop.model import DummyModel

    loop = AgentLoop(
        registry=registry,
        audit=audit_writer,
        model=DummyModel(),
        budget=LoopBudget(max_iterations=5),
    )
    result = loop.run(event)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from core.events.event import Event
from harness.approval.queue import (
    ApprovalEnqueueError,
    ApprovalQueue,
)
from harness.audit.writer import AuditWriter
from harness.permissions.levels import (
    ForbiddenActionError,
    check_level,
)
from harness.policy_engine.engine import PolicyEngine
from harness.policy_engine.policy import Decision, PolicyContext
from harness.tool_registry.registry import (
    ToolNotFoundError,
    ToolRegistry,
)
from harness.tool_registry.tool import Tool, ToolArgumentError

# --- Exceptions ---

class LoopError(Exception):
    """Basis-Exception für Loop-Fehler."""


class BudgetExceededError(LoopError):
    """Budget (Iterationen, Zeit, Tool-Aufrufe) überschritten."""


class ApprovalRequired(LoopError):
    """
    Wird geworfen, wenn ein Tool Level 4 (APPROVAL_REQUIRED) hat.

    Der Loop pausiert. Ein Mensch muss freigeben.
    """

    def __init__(self, tool: Tool, args: dict[str, Any]) -> None:
        super().__init__(
            f"Tool '{tool.name}' (Level 4) benötigt Freigabe. "
            f"Args: {args}"
        )
        self.tool = tool
        # A934: nicht self.args (ueberschreibt
        # BaseException.args, tuple). Eigener Name.
        self.tool_args = args


# --- Budget ---

@dataclass
class LoopBudget:
    """Harte Limits für einen Loop-Durchlauf."""
    max_iterations: int = 5
    max_runtime_s: float = 30.0
    max_tool_calls: int = 10

    # Laufzeit-Zähler (intern)
    started_at: float = field(default_factory=time.monotonic)
    iterations: int = 0
    tool_calls: int = 0

    def check_iteration(self) -> None:
        self.iterations += 1
        if self.iterations > self.max_iterations:
            raise BudgetExceededError(
                f"max_iterations überschritten ({self.max_iterations})"
            )

    def check_runtime(self) -> None:
        elapsed = time.monotonic() - self.started_at
        if elapsed > self.max_runtime_s:
            raise BudgetExceededError(
                f"max_runtime_s überschritten ({self.max_runtime_s}s, "
                f"tatsächlich {elapsed:.2f}s)"
            )

    def check_tool_call(self) -> None:
        self.tool_calls += 1
        if self.tool_calls > self.max_tool_calls:
            raise BudgetExceededError(
                f"max_tool_calls überschritten ({self.max_tool_calls})"
            )


# --- Modell-Interface ---

class Model(Protocol):
    """
    Interface für ein Sprach-/Reasoning-Modell.

    Der Loop ruft nur plan() auf. Alles andere ist Sache des Modells.
    """

    def plan(self, event: Event, context: dict[str, Any]) -> Plan:
        """Erzeugt einen Plan aus Event und Kontext."""
        ...


# --- Plan ---

@dataclass
class PlanStep:
    """Ein einzelner Schritt im Plan."""
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


@dataclass
class Plan:
    """Ein Plan besteht aus null oder mehr Schritten."""
    steps: list[PlanStep] = field(default_factory=list)
    summary: str = ""


# --- Ergebnis ---

@dataclass
class StepResult:
    """Ergebnis eines einzelnen Schritts."""
    tool: str
    status: str           # "OK", "SKIPPED", "ERROR", "APPROVAL_REQUIRED"
    output: Any = None
    error: str | None = None
    duration_ms: int = 0


@dataclass
class LoopResult:
    """Ergebnis eines Loop-Durchlaufs."""
    event_id: str
    started_at: datetime
    finished_at: datetime
    status: str            # "OK", "APPROVAL_REQUIRED", "ERROR", "BUDGET_EXCEEDED"
    steps: list[StepResult] = field(default_factory=list)
    error: str | None = None
    approval_request_id: str | None = None


# --- Agent Loop ---

class AgentLoop:
    """
    Der Agent Loop.

    Führt einen Plan aus, prüft dabei Policy und Permissions,
    auditiert jede Aktion und respektiert ein Budget.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        audit: AuditWriter,
        model: Model,
        budget: LoopBudget | None = None,
        network_id: str = "homelab-default",
        policy_engine: PolicyEngine | None = None,
        approval_queue: ApprovalQueue | None = None,
    ) -> None:
        self.registry = registry
        self.audit = audit
        self.model = model
        self.budget = budget or LoopBudget()
        self.network_id = network_id
        self.policy_engine = policy_engine
        self.approval_queue = approval_queue

    def run(
        self,
        event: Event,
        policy_context: PolicyContext | None = None,
    ) -> LoopResult:
        """
        Führt den Loop für ein Event aus.

        Rückgabe: LoopResult mit Status und Schritten.
        """
        started_at = datetime.now(UTC)
        steps: list[StepResult] = []

        try:
            # CONTEXT — aktuell minimal. Später: DB-Zugriff, Historie.
            context: dict[str, Any] = {
                "network_id": self.network_id,
                "event": event.to_dict(),
            }

            # MODEL — Plan erzeugen
            self.budget.check_runtime()
            plan = self.model.plan(event, context)

            # PLAN ausführen
            for step in plan.steps:
                self.budget.check_iteration()
                self.budget.check_runtime()

                result = self._execute_step(
                    step, event, policy_context=policy_context,
                )
                steps.append(result)

                if result.status == "APPROVAL_REQUIRED":
                    rid: str | None = None
                    if (isinstance(result.output, dict)
                            and "approval_request_id" in result.output):
                        rid = result.output["approval_request_id"]
                    return LoopResult(
                        event_id=event.event_id,
                        started_at=started_at,
                        finished_at=datetime.now(UTC),
                        status="APPROVAL_REQUIRED",
                        steps=steps,
                        approval_request_id=rid,
                    )

            return LoopResult(
                event_id=event.event_id,
                started_at=started_at,
                finished_at=datetime.now(UTC),
                status="OK",
                steps=steps,
            )

        except BudgetExceededError as exc:
            self.audit.log(
                agent="agent_loop",
                tool="loop",
                policy_result="DENIED",
                permission_level=0,
                execution_status="BUDGET_EXCEEDED",
                error=str(exc),
                details={
                    "kind": "loop_error",
                    "error": str(exc),
                },
                network_id=self.network_id,
            )
            return LoopResult(
                event_id=event.event_id,
                started_at=started_at,
                finished_at=datetime.now(UTC),
                status="BUDGET_EXCEEDED",
                steps=steps,
                error=str(exc),
            )

        except Exception as exc:  # noqa: BLE001 - Audit loop_error
            self.audit.log(
                agent="agent_loop",
                tool="loop",
                policy_result="DENIED",
                permission_level=0,
                execution_status="ERROR",
                error=f"{type(exc).__name__}: {exc}",
                details={
                    "kind": "loop_error",
                    "error": f"{type(exc).__name__}: {exc}",
                },
                network_id=self.network_id,
            )
            return LoopResult(
                event_id=event.event_id,
                started_at=started_at,
                finished_at=datetime.now(UTC),
                status="ERROR",
                steps=steps,
                error=f"{type(exc).__name__}: {exc}",
            )

    # --- interne Methoden ---

    def _execute_step(
        self,
        step: PlanStep,
        event: Event,
        policy_context: PolicyContext | None = None,
    ) -> StepResult:
        """Führt einen einzelnen Plan-Schritt aus."""
        started = time.monotonic()

        # TOOL SELECTION
        try:
            tool = self.registry.get(step.tool)
        except ToolNotFoundError as exc:
            self.audit.log(
                agent="agent_loop",
                tool=step.tool,
                policy_result="DENIED",
                permission_level=0,
                execution_status="TOOL_NOT_FOUND",
                error=str(exc),
                details={
                    "kind": "tool_not_found",
                    "tool": step.tool,
                },
                network_id=self.network_id,
            )
            return StepResult(
                tool=step.tool,
                status="ERROR",
                error=str(exc),
                duration_ms=int((time.monotonic() - started) * 1000),
            )

        # PERMISSION CHECK
        try:
            check_level(tool.level, context=f"tool={tool.name}")
        except ForbiddenActionError as exc:
            self.audit.log(
                agent="agent_loop",
                tool=tool.name,
                policy_result="FORBIDDEN",
                permission_level=int(tool.level),
                execution_status="FORBIDDEN",
                args=step.args,
                error=str(exc),
                details={
                    "kind": "tool_denied",
                    "tool": tool.name,
                    "level": int(tool.level),
                    "reason": str(exc),
                    "policy_decision": "FORBIDDEN",
                },
                network_id=self.network_id,
            )
            return StepResult(
                tool=tool.name,
                status="ERROR",
                error=f"FORBIDDEN: {exc}",
                duration_ms=int((time.monotonic() - started) * 1000),
            )

        # APPROVAL REQUIRED — Loop pausiert
        if tool.level.requires_approval:
            approval_request_id: str | None = None
            if self.approval_queue is not None:
                try:
                    req = self.approval_queue.enqueue(
                        tool_name=tool.name,
                        args=step.args,
                        requested_by="security_ai",
                        reason="level_4_requires_approval",
                        event_id=event.event_id,
                    )
                    approval_request_id = req.request_id
                except ApprovalEnqueueError as exc:
                    self.audit.log(
                        agent="security_ai",
                        tool="agent_loop",
                        policy_result="DENIED",
                        permission_level=int(tool.level),
                        execution_status="ENQUEUE_FAILED",
                        error=str(exc),
                        details={"kind": "approval_enqueue_failed"},
                        network_id=self.network_id,
                    )
                    raise
            self.audit.log(
                agent="agent_loop",
                tool=tool.name,
                policy_result="APPROVAL_REQUIRED",
                permission_level=int(tool.level),
                execution_status="PENDING_APPROVAL",
                args=step.args,
                details={
                    "kind": "tool_approval_required",
                    "tool": tool.name,
                    "level": int(tool.level),
                    "reason": "Level 4",
                    "approval_request_id": approval_request_id,
                },
                network_id=self.network_id,
            )
            return StepResult(
                tool=tool.name,
                status="APPROVAL_REQUIRED",
                output={"approval_request_id": approval_request_id},
                duration_ms=int((time.monotonic() - started) * 1000),
            )

        # POLICY CHECK
        if self.policy_engine is not None and policy_context is not None:
            decision = self.policy_engine.evaluate(
                tool.name, step.args, policy_context
            )

            if decision.decision is Decision.FORBIDDEN:
                self.audit.log(
                    agent="agent_loop",
                    tool=tool.name,
                    policy_result="FORBIDDEN",
                    permission_level=int(tool.level),
                    execution_status="POLICY_FORBIDDEN",
                    args=step.args,
                    error=f"POLICY: {decision.reason}",
                    details={
                        "kind": "tool_denied",
                        "tool": tool.name,
                        "level": int(tool.level),
                        "reason": decision.reason,
                        "policy_decision": decision.decision.value,
                        "failed_predicates": list(decision.failed_predicates),
                    },
                    network_id=self.network_id,
                )
                return StepResult(
                    tool=tool.name,
                    status="ERROR",
                    error=f"POLICY: {decision.reason}",
                    duration_ms=int((time.monotonic() - started) * 1000),
                )

            if decision.decision is Decision.APPROVAL_REQUIRED:
                approval_request_id: str | None = None
                if self.approval_queue is not None:
                    try:
                        req = self.approval_queue.enqueue(
                            tool_name=tool.name,
                            args=step.args,
                            requested_by="security_ai",
                            reason=decision.reason,
                            event_id=event.event_id,
                        )
                        approval_request_id = req.request_id
                    except ApprovalEnqueueError as exc:
                        self.audit.log(
                            agent="security_ai",
                            tool="agent_loop",
                            policy_result="DENIED",
                            permission_level=int(tool.level),
                            execution_status="ENQUEUE_FAILED",
                            error=str(exc),
                            details={"kind": "approval_enqueue_failed"},
                            network_id=self.network_id,
                        )
                        raise
                self.audit.log(
                    agent="agent_loop",
                    tool=tool.name,
                    policy_result="APPROVAL_REQUIRED",
                    permission_level=int(tool.level),
                    execution_status="PENDING_APPROVAL",
                    args=step.args,
                    error=f"POLICY: {decision.reason}",
                    details={
                        "kind": "tool_approval_required",
                        "tool": tool.name,
                        "level": int(tool.level),
                        "reason": decision.reason,
                        "policy_decision": decision.decision.value,
                        "failed_predicates": list(decision.failed_predicates),
                        "approval_request_id": approval_request_id,
                    },
                    network_id=self.network_id,
                )
                return StepResult(
                    tool=tool.name,
                    status="APPROVAL_REQUIRED",
                    output={"approval_request_id": approval_request_id},
                    error=f"POLICY: {decision.reason}",
                    duration_ms=int((time.monotonic() - started) * 1000),
                )

            # ALLOWED: faellt durch zur Argument-Validierung

        # ARGUMENT-VALIDIERUNG
        try:
            tool.validate_args(step.args)
        except ToolArgumentError as exc:
            self.audit.log(
                agent="agent_loop",
                tool=tool.name,
                policy_result="DENIED",
                permission_level=int(tool.level),
                execution_status="INVALID_ARGS",
                args=step.args,
                error=str(exc),
                details={
                    "kind": "tool_invalid_args",
                    "tool": tool.name,
                    "reason": str(exc),
                },
                network_id=self.network_id,
            )
            return StepResult(
                tool=tool.name,
                status="ERROR",
                error=str(exc),
                duration_ms=int((time.monotonic() - started) * 1000),
            )

        # EXECUTION
        self.budget.check_tool_call()
        try:
            output = tool.func(**step.args)
            duration_ms = int((time.monotonic() - started) * 1000)
            self.audit.log(
                agent="agent_loop",
                tool=tool.name,
                policy_result="ALLOWED",
                permission_level=int(tool.level),
                execution_status="OK",
                args=step.args,
                duration_ms=duration_ms,
                details={
                    "kind": "tool_call",
                    "tool": tool.name,
                    "level": int(tool.level),
                    "duration_ms": duration_ms,
                },
                network_id=self.network_id,
            )
            return StepResult(
                tool=tool.name,
                status="OK",
                output=output,
                duration_ms=duration_ms,
            )
        except Exception as exc:  # noqa: BLE001 - Tool darf alles werfen
            duration_ms = int((time.monotonic() - started) * 1000)
            self.audit.log(
                agent="agent_loop",
                tool=tool.name,
                policy_result="ALLOWED",
                permission_level=int(tool.level),
                execution_status="ERROR",
                args=step.args,
                duration_ms=duration_ms,
                error=f"{type(exc).__name__}: {exc}",
                details={
                    "kind": "tool_call",
                    "tool": tool.name,
                    "level": int(tool.level),
                    "duration_ms": duration_ms,
                    "error": f"{type(exc).__name__}: {exc}",
                },
                network_id=self.network_id,
            )
            return StepResult(
                tool=tool.name,
                status="ERROR",
                error=f"{type(exc).__name__}: {exc}",
                duration_ms=duration_ms,
            )


__all__ = [
    "AgentLoop",
    "ApprovalRequired",
    "BudgetExceededError",
    "LoopBudget",
    "LoopError",
    "LoopResult",
    "Model",
    "Plan",
    "PlanStep",
    "StepResult",
]
