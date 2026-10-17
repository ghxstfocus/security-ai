"""Doku-Pruefung: docs/SECURITY_LOG.md enthaelt den Phase-19-Detail-Eintrag."""

from pathlib import Path

import pytest

SECURITY_LOG_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "SECURITY_LOG.md"
)


@pytest.fixture(scope="module")
def security_log_text() -> str:
    assert SECURITY_LOG_PATH.is_file(), (
        f"SECURITY_LOG.md fehlt: {SECURITY_LOG_PATH}"
    )
    return SECURITY_LOG_PATH.read_text(encoding="utf-8")


def test_phase_19_detail_eintrag_vorhanden(security_log_text: str) -> None:
    assert "## Phase 19 — Sofort-Massnahmen" in security_log_text


def test_phase_19_destruktive_aktionen(security_log_text: str) -> None:
    idx = security_log_text.find("## Phase 19 — Sofort-Massnahmen")
    assert idx != -1
    abschnitt = security_log_text[idx:]
    assert "BLOCK" in abschnitt
    assert "ISOLATE" in abschnitt


def test_phase_19_berechtigung_dokumentiert(security_log_text: str) -> None:
    idx = security_log_text.find("## Phase 19 — Sofort-Massnahmen")
    assert idx != -1
    abschnitt = security_log_text[idx:]
    assert "sofortmassnahme.execute" in abschnitt


def test_phase_19_audit_pflicht_dokumentiert(security_log_text: str) -> None:
    idx = security_log_text.find("## Phase 19 — Sofort-Massnahmen")
    assert idx != -1
    abschnitt = security_log_text[idx:]
    assert "sofortmassnahme_executed" in abschnitt


def test_phase_19_detail_eintrag_vor_zweck(security_log_text: str) -> None:
    detail = security_log_text.find("## Phase 19 — Sofort-Massnahmen")
    zweck = security_log_text.find("## Zweck")
    assert detail != -1
    assert zweck != -1
    assert detail < zweck