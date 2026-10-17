"""Tests fuer core/changeapplier/models.py und das Paket."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from core.changeapplier import Change, ChangeApplier, ChangeState


def test_paket_reexport() -> None:
    """Die drei Symbole sind aus dem Paket importierbar."""
    import core.changeapplier as pkg

    # U1-Fix (2026-10-17): Mengenvergleich statt Liste.
    # Grund: RUF022 sortiert __all__ isort-style. Ein Listen-
    # Vergleich koppelt den Test an die Sortierung und bricht
    # bei jedem Auto-Fix. Mengenvergleich prueft die Semantik
    # (drei Symbole re-exportiert), nicht die Reihenfolge.
    assert set(pkg.__all__) == {
        "ChangeApplier", "Change", "ChangeState"}
    assert pkg.ChangeApplier is ChangeApplier
    assert pkg.Change is Change
    assert pkg.ChangeState is ChangeState


def test_changestate_hat_genau_vier_werte() -> None:
    assert len(ChangeState) == 4
    assert {s.name for s in ChangeState} == {
        "PENDING",
        "APPLIED",
        "ROLLED_BACK",
        "FAILED",
    }


def test_change_default_state_ist_pending() -> None:
    change = Change(id="c1", target="config.yaml", payload={"a": 1})
    assert change.state is ChangeState.PENDING
    assert change.applied_at is None


def test_changeapplier_instanziierbar(tmp_path: Path) -> None:
    applier = ChangeApplier(tmp_path / "config.yaml")
    assert applier.config_path == tmp_path / "config.yaml"


def test_apply_und_rollback_signaturen(tmp_path: Path) -> None:
    applier = ChangeApplier(tmp_path / "config.yaml")
    change = Change(id="c1", target="config.yaml", payload={})
    with pytest.raises(NotImplementedError):
        applier.apply(change)
    with pytest.raises(NotImplementedError):
        applier.rollback(change)


def test_gueltiger_uebergang_pending_nach_applied() -> None:
    change = Change(id="c1", target="config.yaml", payload={})
    change.transition_to(ChangeState.APPLIED)
    assert change.state is ChangeState.APPLIED


def test_gueltiger_uebergang_pending_nach_failed() -> None:
    change = Change(id="c1", target="config.yaml", payload={})
    change.transition_to(ChangeState.FAILED)
    assert change.state is ChangeState.FAILED


def test_gueltiger_uebergang_applied_nach_rolled_back() -> None:
    change = Change(id="c1", target="config.yaml", payload={})
    change.transition_to(ChangeState.APPLIED)
    change.transition_to(ChangeState.ROLLED_BACK)
    assert change.state is ChangeState.ROLLED_BACK


def test_ungueltiger_uebergang_applied_nach_pending() -> None:
    change = Change(id="c1", target="config.yaml", payload={})
    change.transition_to(ChangeState.APPLIED)
    with pytest.raises(ValueError):
        change.transition_to(ChangeState.PENDING)


def test_ungueltiger_uebergang_rolled_back_nach_applied() -> None:
    change = Change(id="c1", target="config.yaml", payload={})
    change.transition_to(ChangeState.APPLIED)
    change.transition_to(ChangeState.ROLLED_BACK)
    with pytest.raises(ValueError):
        change.transition_to(ChangeState.APPLIED)


def test_ungueltiger_uebergang_failed_nach_applied() -> None:
    change = Change(id="c1", target="config.yaml", payload={})
    change.transition_to(ChangeState.FAILED)
    with pytest.raises(ValueError):
        change.transition_to(ChangeState.APPLIED)


def test_applied_at_setzbar() -> None:
    now = datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC)
    change = Change(
        id="c1",
        target="config.yaml",
        payload={},
        applied_at=now,
    )
    assert change.applied_at == now