"""Doku-Pruefung: docs/DECISIONS.md enthaelt Paragraph 30."""

from pathlib import Path

import pytest

DECISIONS_PATH = Path(__file__).resolve().parents[2] / "docs" / "DECISIONS.md"


@pytest.fixture(scope="module")
def decisions_text() -> str:
    assert DECISIONS_PATH.is_file(), f"DECISIONS.md fehlt: {DECISIONS_PATH}"
    return DECISIONS_PATH.read_text(encoding="utf-8")


def test_paragraph_30_vorhanden(decisions_text: str) -> None:
    assert "## 30. ChangeApplier und Sofort-Massnahmen-Kategorie" in decisions_text


def test_paragraph_30_fail_closed_dokumentiert(decisions_text: str) -> None:
    idx = decisions_text.find("## 30. ChangeApplier")
    assert idx != -1
    abschnitt = decisions_text[idx:]
    assert "Fail closed" in abschnitt


def test_paragraph_30_backup_restore_dokumentiert(decisions_text: str) -> None:
    idx = decisions_text.find("## 30. ChangeApplier")
    assert idx != -1
    abschnitt = decisions_text[idx:]
    assert "Backup/Restore" in abschnitt


def test_paragraph_30_idempotenz_dokumentiert(decisions_text: str) -> None:
    idx = decisions_text.find("## 30. ChangeApplier")
    assert idx != -1
    abschnitt = decisions_text[idx:]
    assert "Idempotenz" in abschnitt


def test_paragraph_30_vor_design_entscheidungen(decisions_text: str) -> None:
    p30 = decisions_text.find("## 30. ChangeApplier")
    p1 = decisions_text.find("## 1. Design-Entscheidungen")
    assert p30 != -1
    assert p1 != -1
    assert p30 < p1