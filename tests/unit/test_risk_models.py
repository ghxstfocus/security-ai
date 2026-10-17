# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer die Sofort-Massnahmen-Kategorie im Risk-Modell."""
from __future__ import annotations

import pytest

from core.risk.models import (
    ImmediateActionCategory,
    RiskCategory,
    risk_level_to_immediate_action,
)


def test_immediate_action_category_hat_vier_werte() -> None:
    assert set(ImmediateActionCategory) == {
        ImmediateActionCategory.BLOCK,
        ImmediateActionCategory.ISOLATE,
        ImmediateActionCategory.ALERT,
        ImmediateActionCategory.LOG_ONLY,
    }


def test_mapping_confirmed_security_alert_suspicion_anomaly_event() -> None:
    assert (
        risk_level_to_immediate_action(RiskCategory.CONFIRMED)
        is ImmediateActionCategory.BLOCK
    )
    assert (
        risk_level_to_immediate_action(RiskCategory.SECURITY_ALERT)
        is ImmediateActionCategory.ISOLATE
    )
    assert (
        risk_level_to_immediate_action(RiskCategory.SUSPICION)
        is ImmediateActionCategory.ALERT
    )
    assert (
        risk_level_to_immediate_action(RiskCategory.ANOMALY)
        is ImmediateActionCategory.LOG_ONLY
    )
    assert (
        risk_level_to_immediate_action(RiskCategory.EVENT)
        is ImmediateActionCategory.LOG_ONLY
    )


def test_mapping_unbekannt_wirft_valueerror() -> None:
    with pytest.raises(ValueError):
        risk_level_to_immediate_action("UNKNOWN")  # type: ignore[arg-type]


def test_symbole_importierbar() -> None:
    from core.risk import models

    assert hasattr(models, "ImmediateActionCategory")
    assert hasattr(models, "risk_level_to_immediate_action")
    assert "ImmediateActionCategory" in models.__all__
    assert "risk_level_to_immediate_action" in models.__all__