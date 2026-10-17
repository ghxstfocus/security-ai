"""Doku-Pruefung: docs/STATUS.md enthaelt den Phase-19-Abschnitt."""

from pathlib import Path

import pytest

STATUS_PATH = Path(__file__).resolve().parents[2] / "docs" / "STATUS.md"


@pytest.fixture(scope="module")
def status_text() -> str:
    assert STATUS_PATH.is_file(), f"STATUS.md fehlt: {STATUS_PATH}"
    return STATUS_PATH.read_text(encoding="utf-8")


def test_phase_19_abschnitt_vorhanden(status_text: str) -> None:
    assert "## Phase 19" in status_text


def test_phase_19_unterbloecke_gelistet(status_text: str) -> None:
    for marker in ("U1", "U2", "U3", "U4", "U5"):
        assert marker in status_text, f"Unterblock {marker} fehlt"


def test_phase_19_verweis_changeapplier(status_text: str) -> None:
    assert "ChangeApplier" in status_text


def test_phase_19_verweis_sofortmassnahmen(status_text: str) -> None:
    assert "Sofort-Massnahmen" in status_text


def test_phase_19_vor_naechstem_bau_block(status_text: str) -> None:
    phase_pos = status_text.find("## Phase 19")
    naechster_pos = status_text.find("## Naechster Bau-Block")
    assert phase_pos != -1
    assert naechster_pos != -1
    assert phase_pos < naechster_pos