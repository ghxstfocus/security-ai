"""
Tests für den Agent Loop.

Prüft die Sicherheitsgarantien:
- Level 0/1: automatisch ausgeführt
- Level 4: pausiert mit APPROVAL_REQUIRED
- Level 5: blockiert mit FORBIDDEN
- Unbekanntes Tool: ERROR + Audit
- Ungültige Args: ERROR + Audit
- Budget-Überschreitung: BUDGET_EXCEEDED
- Jede Aktion wird auditiert
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from core.events.event import Event, Severity, new_event
from harness.agent_loop.loop import (
    AgentLoop,
    BudgetExceededError,
    LoopBudget,
)
from harness.agent_loop.model import DummyModel
from harness.audit.writer import AuditWriter
from harness.permissions.levels import Level
from harness.tool_registry.registry import ToolRegistry
from harness.tool_registry.tool import Tool


# --- Fixtures ---

@pytest.fixture
def tmp_audit_dir(tmp_path: Path) -> Path:
    return tmp_path / "audit-logs"


@pytest.fixture
def audit(tmp_audit_dir: Path) -> AuditWriter:
    return AuditWriter(base_dir=tmp_audit_dir)


@pytest.fixture
def registry() -> ToolRegistry:
    reg = ToolRegistry()

    reg.register(Tool(
        name="read_logs",
        level=Level.READ,
        func=lambda file="x": f"logs from {file}",
        description="Logs lesen",
        sandbox_profile="read_only",
        allowed_args=frozenset({"file"}),
    ))

    reg.register(Tool(
        name="send_alert",
        level=Level.SECURITY_ACTION,
        func=lambda message="": f"sent: {message}",
        description="Telegram-Alarm",
        sandbox_profile="no_network_except_telegram",
        allowed_args=frozenset({"message"}),
    ))

    reg.register(Tool(
        name="change_firewall",
        level=Level.APPROVAL_REQUIRED,
        func=lambda rule="": f"changed: {rule}",
        description="Firewall-Regel ändern",
        sandbox_profile="local_filesystem",
        allowed_args=frozenset({"rule"}),
    ))

    reg.register(Tool(
        name="execute_shell",
        level=Level.FORBIDDEN,
        func=lambda cmd="": "should never run",
        description="Shell ausführen (verboten)",
        sandbox_profile=None,
        allowed_args=frozenset({"cmd"}),
    ))

    return reg


@pytest.fixture
def sample_event() -> Event:
    return new_event(
        source="test",
        event_type="device_presence",
        severity=Severity.INFO,
        data={"identifier": "192.168.178.99"},
    )


# --- Tests: Happy Path ---

def test_level0_tool_is_executed(registry, audit, sample_event):
    """Level 0 (READ) wird automatisch ausgeführt und auditiert."""
    model = DummyModel(fixed_steps=[
        __import__("harness.agent_loop.loop", fromlist=["PlanStep"]).PlanStep(
            tool="read_logs", args={"file": "auth.log"}, reason="check logs"
        ),
    ])
    loop = AgentLoop(registry=registry, audit=audit, model=model)
    result = loop.run(sample_event)

    assert result.status == "OK"
    assert len(result.steps) == 1
    assert result.steps[0].status == "OK"
    assert "logs from auth.log" in result.steps[0].output


def test_level1_tool_is_executed(registry, audit, sample_event):
    """Level 1 (SECURITY_ACTION) wird automatisch ausgeführt."""
    from harness.agent_loop.loop import PlanStep
    model = DummyModel(fixed_steps=[
        PlanStep(tool="send_alert", args={"message": "test alert"}),
    ])
    loop = AgentLoop(registry=registry, audit=audit, model=model)
    result = loop.run(sample_event)

    assert result.status == "OK"
    assert result.steps[0].status == "OK"


# --- Tests: Sicherheitsgarantien ---

def test_level4_pauses_for_approval(registry, audit, sample_event):
    """Level 4 (APPROVAL_REQUIRED) pausiert und wartet auf Freigabe."""
    from harness.agent_loop.loop import PlanStep
    model = DummyModel(fixed_steps=[
        PlanStep(tool="change_firewall", args={"rule": "allow 8080"}),
    ])
    loop = AgentLoop(registry=registry, audit=audit, model=model)
    result = loop.run(sample_event)

    assert result.status == "APPROVAL_REQUIRED"
    assert result.steps[0].status == "APPROVAL_REQUIRED"


def test_level5_is_blocked(registry, audit, sample_event):
    """Level 5 (FORBIDDEN) wird niemals ausgeführt."""
    from harness.agent_loop.loop import PlanStep
    model = DummyModel(fixed_steps=[
        PlanStep(tool="execute_shell", args={"cmd": "rm -rf /"}),
    ])
    loop = AgentLoop(registry=registry, audit=audit, model=model)
    result = loop.run(sample_event)

    assert result.status == "OK"  # Loop läuft weiter, aber Schritt ist ERROR
    assert result.steps[0].status == "ERROR"
    assert "FORBIDDEN" in result.steps[0].error


def test_unknown_tool_is_rejected(registry, audit, sample_event):
    """Unbekanntes Tool wird abgelehnt."""
    from harness.agent_loop.loop import PlanStep
    model = DummyModel(fixed_steps=[
        PlanStep(tool="does_not_exist", args={}),
    ])
    loop = AgentLoop(registry=registry, audit=audit, model=model)
    result = loop.run(sample_event)

    assert result.steps[0].status == "ERROR"
    assert "nicht registriert" in result.steps[0].error


def test_invalid_args_are_rejected(registry, audit, sample_event):
    """Unerlaubte Argumente werden abgelehnt."""
    from harness.agent_loop.loop import PlanStep
    model = DummyModel(fixed_steps=[
        PlanStep(tool="read_logs", args={"evil_param": "/etc/shadow"}),
    ])
    loop = AgentLoop(registry=registry, audit=audit, model=model)
    result = loop.run(sample_event)

    assert result.steps[0].status == "ERROR"
    assert "unbekannte argumente" in result.steps[0].error.lower()


# --- Tests: Budget ---

def test_budget_max_iterations(registry, audit, sample_event):
    """Zu viele Iterationen führen zu BUDGET_EXCEEDED."""
    from harness.agent_loop.loop import PlanStep
    model = DummyModel(fixed_steps=[
        PlanStep(tool="read_logs", args={"file": f"log{i}.txt"})
        for i in range(10)
    ])
    budget = LoopBudget(max_iterations=3)
    loop = AgentLoop(registry=registry, audit=audit, model=model, budget=budget)
    result = loop.run(sample_event)

    assert result.status == "BUDGET_EXCEEDED"


def test_budget_max_tool_calls(registry, audit, sample_event):
    """Zu viele Tool-Aufrufe führen zu BUDGET_EXCEEDED."""
    from harness.agent_loop.loop import PlanStep
    model = DummyModel(fixed_steps=[
        PlanStep(tool="read_logs", args={"file": f"log{i}.txt"})
        for i in range(10)
    ])
    budget = LoopBudget(max_iterations=100, max_tool_calls=2)
    loop = AgentLoop(registry=registry, audit=audit, model=model, budget=budget)
    result = loop.run(sample_event)

    assert result.status == "BUDGET_EXCEEDED"


# --- Tests: Audit ---

def test_every_step_is_audited(registry, audit, sample_event):
    """Jeder Schritt wird auditiert."""
    from harness.agent_loop.loop import PlanStep
    model = DummyModel(fixed_steps=[
        PlanStep(tool="read_logs", args={"file": "a.log"}),
        PlanStep(tool="send_alert", args={"message": "hi"}),
    ])
    loop = AgentLoop(registry=registry, audit=audit, model=model)
    result = loop.run(sample_event)

    assert result.status == "OK"
    entries = audit.read_day()
    # 2 Schritte → 2 Audit-Einträge
    assert len(entries) == 2
    tools = [e.tool for e in entries]
    assert "read_logs" in tools
    assert "send_alert" in tools
    # Alle erlaubt
    assert all(e.policy_result == "ALLOWED" for e in entries)


def test_forbidden_is_audited(registry, audit, sample_event):
    """Verbotene Aktionen werden auditiert."""
    from harness.agent_loop.loop import PlanStep
    model = DummyModel(fixed_steps=[
        PlanStep(tool="execute_shell", args={"cmd": "rm -rf /"}),
    ])
    loop = AgentLoop(registry=registry, audit=audit, model=model)
    loop.run(sample_event)

    entries = audit.read_day()
    assert len(entries) == 1
    assert entries[0].policy_result == "FORBIDDEN"
    assert entries[0].execution_status == "FORBIDDEN"


def test_approval_request_is_audited(registry, audit, sample_event):
    """Freigabe-Anfragen werden auditiert."""
    from harness.agent_loop.loop import PlanStep
    model = DummyModel(fixed_steps=[
        PlanStep(tool="change_firewall", args={"rule": "allow"}),
    ])
    loop = AgentLoop(registry=registry, audit=audit, model=model)
    loop.run(sample_event)

    entries = audit.read_day()
    assert len(entries) == 1
    assert entries[0].policy_result == "APPROVAL_REQUIRED"
    assert entries[0].execution_status == "PENDING_APPROVAL"


# --- Tests: Modell ---

def test_empty_plan_is_ok(registry, audit, sample_event):
    """Leerer Plan führt zu Status OK ohne Schritte."""
    model = DummyModel(fixed_steps=[])
    loop = AgentLoop(registry=registry, audit=audit, model=model)
    result = loop.run(sample_event)

    assert result.status == "OK"
    assert len(result.steps) == 0
