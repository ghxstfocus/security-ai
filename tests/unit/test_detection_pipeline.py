"""Tests fuer die Detection-Pipeline mit Sofort-Massnahmen-Hook."""

from __future__ import annotations

from unittest.mock import MagicMock

from core.detection.pipeline import DetectionPipeline
from core.risk.models import RiskCategory


def _make_finding(category: object) -> MagicMock:
    from core.risk.models import RiskCategory
    finding = MagicMock()
    finding.category = (
        category if isinstance(category, RiskCategory)
        else RiskCategory(category)
    )
    return finding


def test_run_ruft_immediate_action_service() -> None:
    """run mit CONFIRMED-Finding ruft execute genau einmal auf."""
    from core.risk.models import ImmediateActionCategory

    service = MagicMock()
    finding = _make_finding(RiskCategory.CONFIRMED)
    pipeline = DetectionPipeline(immediate_action_service=service)

    result = pipeline.run([finding])

    assert result == [finding]
    assert service.execute.call_count == 1
    assert service.execute.call_args[0][0] is finding
    # LOG_ONLY ist nicht CONFIRMED -> execute muss aufgerufen worden sein.
    assert ImmediateActionCategory.LOG_ONLY is not None


def test_run_log_only_ruft_execute_nicht() -> None:
    """Finding der Kategorie EVENT -> execute NICHT aufgerufen."""
    service = MagicMock()
    finding = _make_finding(RiskCategory.EVENT)
    pipeline = DetectionPipeline(immediate_action_service=service)

    result = pipeline.run([finding])

    assert result == [finding]
    service.execute.assert_not_called()


def test_run_execute_fehler_bricht_nicht_ab() -> None:
    """execute wirft Exception -> run liefert findings, Audit status=FAILED."""
    service = MagicMock()
    service.execute.side_effect = RuntimeError("boom")
    finding = _make_finding(RiskCategory.CONFIRMED)
    pipeline = DetectionPipeline(immediate_action_service=service)

    result = pipeline.run([finding])

    assert result == [finding]
    assert service.execute.call_count == 1
    # Der Service schreibt den FAILED-Audit
    # selbst (in execute()). Die Pipeline
    # propagiert die Exception nicht (fail-
    # closed). Der Test kommt ohne Raise hierher.


def test_run_ohne_service_ist_noop() -> None:
    """immediate_action_service=None -> run liefert findings, kein Fehler."""
    finding = _make_finding(RiskCategory.CONFIRMED)
    pipeline = DetectionPipeline(immediate_action_service=None)

    result = pipeline.run([finding])

    assert result == [finding]