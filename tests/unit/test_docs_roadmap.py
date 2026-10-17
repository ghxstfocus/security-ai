"""Doku-Pruefung: docs/ROADMAP.md enthaelt den Phase-19-Abschnitt."""

from pathlib import Path

import pytest

ROADMAP_PATH = Path(__file__).resolve().parents[2] / "docs" / "ROADMAP.md"


@pytest.fixture(scope="module")
def roadmap_text() -> str:
    assert ROADMAP_PATH.is_file(), f"ROADMAP.md fehlt: {ROADMAP_PATH}"
    return ROADMAP_PATH.read_text(encoding="utf-8")


def test_phase_19_abschnitt_vorhanden(roadmap_text: str) -> None:
    assert "## Phase 19" in roadmap_text


def test_phase_19_mit_icon_abgeschlossen(roadmap_text: str) -> None:
    idx = roadmap_text.find("## Phase 19")
    assert idx != -1
    zeile = roadmap_text[idx:].splitlines()[0]
    assert "\u2705" in zeile, f"Status-Icon fehlt: {zeile!r}"


def test_phase_19_unterbloecke_referenziert(roadmap_text: str) -> None:
    for marker in ("U1", "U2", "U3", "U4", "U5"):
        assert marker in roadmap_text, f"Unterblock {marker} fehlt"


def test_phase_19_changeapplier_und_sofortmassnahmen(roadmap_text: str) -> None:
    assert "ChangeApplier" in roadmap_text
    assert "Sofort-Massnahmen" in roadmap_text