"""Doku-Pruefung: ADR-0030 (ChangeApplier) enthaelt die relevanten Punkte.

OP-005 (2026-10-31): docs/DECISIONS.md wurde zu 27 ADRs gesplittet
(DOC_CONVENTIONS.md §3). §30 (ChangeApplier und Sofort-Massnahmen) ist
jetzt docs/adr/ADR-0030-changeapplier-und-sofort-massnahmen-kategorie.md.
"""

from pathlib import Path

import pytest

ADR_DIR = Path(__file__).resolve().parents[2] / "docs" / "adr"
ADR_0030_GLOB = "ADR-0030-*.md"
ADR_INDEX = ADR_DIR / "README.md"


@pytest.fixture(scope="module")
def adr_0030_path() -> Path:
    matches = sorted(ADR_DIR.glob(ADR_0030_GLOB))
    assert matches, f"Keine ADR-0030-Datei in {ADR_DIR} (Glob: {ADR_0030_GLOB})"
    return matches[0]


@pytest.fixture(scope="module")
def adr_0030_text(adr_0030_path: Path) -> str:
    return adr_0030_path.read_text(encoding="utf-8")


def test_paragraph_30_vorhanden(adr_0030_text: str) -> None:
    assert "ChangeApplier" in adr_0030_text
    assert "Sofort-Massnahmen" in adr_0030_text


def test_paragraph_30_fail_closed_dokumentiert(adr_0030_text: str) -> None:
    assert "Fail closed" in adr_0030_text or "fail closed" in adr_0030_text


def test_paragraph_30_backup_restore_dokumentiert(adr_0030_text: str) -> None:
    assert "Backup/Restore" in adr_0030_text or "Backup" in adr_0030_text


def test_paragraph_30_idempotenz_dokumentiert(adr_0030_text: str) -> None:
    assert "Idempotenz" in adr_0030_text or "idempotent" in adr_0030_text.lower()


def test_adr_0030_im_index_referenziert() -> None:
    """ADR-0030 ist im docs/adr/README.md-Index gelistet."""
    assert ADR_INDEX.is_file(), f"ADR-Index fehlt: {ADR_INDEX}"
    index_text = ADR_INDEX.read_text(encoding="utf-8")
    assert "0030" in index_text, "ADR-0030 nicht im ADR-Index referenziert"
