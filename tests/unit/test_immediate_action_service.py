"""Tests fuer ImmediateActionService."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from core.risk.models import ImmediateActionCategory
from core.services.immediate_action_service import ImmediateActionService


@dataclass
class _FakeActor:
    permissions: set[str] = field(default_factory=set)


@dataclass
class _FakeFinding:
    id: str
    severity: str = "high"
    actor: Any = None


class _FakeAuditLog:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def record(self, **kwargs: Any) -> None:
        self.entries.append(kwargs)


class _FakeNotifier:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def notify(self, message: str) -> None:
        self.messages.append(message)


def _make_service(
    notifier: _FakeNotifier | None = None,
) -> tuple[ImmediateActionService, _FakeAuditLog]:
    audit = _FakeAuditLog()
    svc = ImmediateActionService(audit_log=audit, notifier=notifier)
    return svc, audit


def test_execute_dispatches_block() -> None:
    svc, audit = _make_service()
    finding = _FakeFinding(
        id="f-1",
        actor=_FakeActor(permissions={"immediate_action.execute"}),
    )
    result = svc.execute(finding, ImmediateActionCategory.BLOCK)
    assert result.status == "SUCCESS"
    assert len(audit.entries) == 1
    assert audit.entries[0]["details"]["status"] == "SUCCESS"
    assert audit.entries[0]["details"]["category"] == "BLOCK"


def test_execute_dispatches_isolate() -> None:
    svc, audit = _make_service()
    finding = _FakeFinding(
        id="f-2",
        actor=_FakeActor(permissions={"immediate_action.execute"}),
    )
    result = svc.execute(finding, ImmediateActionCategory.ISOLATE)
    assert result.status == "SUCCESS"
    assert len(audit.entries) == 1
    assert audit.entries[0]["details"]["category"] == "ISOLATE"


def test_execute_dispatches_alert() -> None:
    notifier = _FakeNotifier()
    svc, audit = _make_service(notifier=notifier)
    finding = _FakeFinding(id="f-3")
    result = svc.execute(finding, ImmediateActionCategory.ALERT)
    assert result.status == "SUCCESS"
    assert len(notifier.messages) == 1
    assert len(audit.entries) == 1
    assert audit.entries[0]["details"]["category"] == "ALERT"


def test_execute_dispatches_log_only() -> None:
    svc, audit = _make_service()
    finding = _FakeFinding(id="f-4")
    result = svc.execute(finding, ImmediateActionCategory.LOG_ONLY)
    assert result.status == "SUCCESS"
    assert len(audit.entries) == 1
    assert audit.entries[0]["details"]["category"] == "LOG_ONLY"


def test_block_without_permission_raises() -> None:
    svc, audit = _make_service()
    finding = _FakeFinding(id="f-5", actor=_FakeActor(permissions=set()))
    with pytest.raises(PermissionError):
        svc.execute(finding, ImmediateActionCategory.BLOCK)
    assert len(audit.entries) == 1
    assert audit.entries[0]["details"]["status"] == "FAILED"


def test_isolate_without_permission_raises() -> None:
    svc, audit = _make_service()
    finding = _FakeFinding(id="f-6", actor=None)
    with pytest.raises(PermissionError):
        svc.execute(finding, ImmediateActionCategory.ISOLATE)
    assert len(audit.entries) == 1
    assert audit.entries[0]["details"]["status"] == "FAILED"


def test_log_only_writes_only_audit() -> None:
    notifier = _FakeNotifier()
    svc, audit = _make_service(notifier=notifier)
    finding = _FakeFinding(id="f-7")
    svc.execute(finding, ImmediateActionCategory.LOG_ONLY)
    assert notifier.messages == []
    assert len(audit.entries) == 1


def test_idempotent_second_call_skips() -> None:
    svc, audit = _make_service()
    finding = _FakeFinding(
        id="f-8",
        actor=_FakeActor(permissions={"immediate_action.execute"}),
    )
    first = svc.execute(finding, ImmediateActionCategory.BLOCK)
    second = svc.execute(finding, ImmediateActionCategory.BLOCK)
    assert first.status == "SUCCESS"
    assert second.status == "SKIPPED"
    assert second.skipped is True
    assert len(audit.entries) == 2
    assert audit.entries[0]["details"]["status"] == "SUCCESS"
    assert audit.entries[1]["details"]["status"] == "SKIPPED"