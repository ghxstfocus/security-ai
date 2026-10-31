"""Doku-Pruefung: PROGRESS.md enthaelt den Phase-19-Abschnitt.

OP-005 (2026-10-31): Phase 19 wurde von docs/STATUS.md nach PROGRESS.md
migriert (DOC_CONVENTIONS.md §1: History vs. Status). Test prueft jetzt
PROGRESS.md.
"""

from pathlib import Path

import pytest

PROGRESS_PATH = Path(__file__).resolve().parents[2] / "PROGRESS.md"


@pytest.fixture(scope="module")
def progress_text() -> str:
    assert PROGRESS_PATH.is_file(), f"PROGRESS.md fehlt: {PROGRESS_PATH}"
    return PROGRESS_PATH.read_text(encoding="utf-8")


def _phase_19_abschnitt(text: str) -> str:
    """Liefert den Text ab '## Phase 19' bis zum naechsten '## '-Header."""
    start = text.find("## Phase 19")
    if start == -1:
        return ""
    rest = text[start + len("## Phase 19"):]
    naechster = rest.find("\n## ")
    return rest if naechster == -1 else rest[:naechster]


def test_phase_19_abschnitt_vorhanden(progress_text: str) -> None:
    assert "## Phase 19" in progress_text


def test_phase_19_unterbloecke_gelistet(progress_text: str) -> None:
    abschnitt = _phase_19_abschnitt(progress_text)
    assert abschnitt, "Phase-19-Abschnitt in PROGRESS.md nicht gefunden"
    for marker in ("U1", "U2", "U3", "U4", "U5"):
        assert marker in abschnitt, f"Unterblock {marker} fehlt in Phase 19"


def test_phase_19_verweis_changeapplier(progress_text: str) -> None:
    abschnitt = _phase_19_abschnitt(progress_text)
    assert "ChangeApplier" in abschnitt


def test_phase_19_verweis_sofortmassnahmen(progress_text: str) -> None:
    abschnitt = _phase_19_abschnitt(progress_text)
    assert "Sofort-Massnahmen" in abschnitt


def test_phase_19_vor_phase_20(progress_text: str) -> None:
    """Phase 19 steht in PROGRESS.md (Phase 20+ sind noch nicht dort)."""
    p19 = progress_text.find("## Phase 19")
    p20 = progress_text.find("## Phase 20")
    assert p19 != -1, "Phase 19 nicht gefunden in PROGRESS.md"
    if p20 != -1:
        # Falls Phase 20 spaeter kommt: 19 muss davor stehen
        assert p19 < p20, "Phase 19 muss vor Phase 20 stehen"
