"""Tests fuer die Projekt-Guardrail-Config.

Laedt core/guardrails/guardrails.yaml ueber den
Loader und prueft Pflichtfelder.

Hinweis zur Anzahl: Der Auftrag nennt "Beispiel-
Guardrails" ohne feste Zahl. Der Test prueft
deshalb nur, dass mindestens ein Eintrag
vorhanden ist (>= 1). Eine harte Kopplung an
eine konkrete Anzahl waere nicht durch Auftrag
oder Doku gedeckt und wuerde jede spaetere
Ergaenzung eines Beispiel-Eintrags brechen.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from core.guardrails.loader import load_guardrails
from core.guardrails.models import (
    Guardrail,
    GuardrailLevel,
    GuardrailState,
)

PROJECT_CONFIG = (
    Path(__file__).resolve().parents[2]
    / "core"
    / "guardrails"
    / "guardrails.yaml"
)


class ProjectGuardrailsConfigTests(unittest.TestCase):
    def test_config_file_exists(self) -> None:
        self.assertTrue(
            PROJECT_CONFIG.is_file(),
            f"Config fehlt: {PROJECT_CONFIG}",
        )

    def test_config_loads(self) -> None:
        result = load_guardrails(PROJECT_CONFIG)
        self.assertIsInstance(result, list)
        for entry in result:
            self.assertIsInstance(entry, Guardrail)

    def test_config_entry_count_at_least_one(self) -> None:
        # Bewusst >= 1, nicht == 4: der Auftrag
        # nennt "Beispiel-Guardrails" ohne feste
        # Anzahl. Siehe Modul-Docstring.
        result = load_guardrails(PROJECT_CONFIG)
        self.assertGreaterEqual(len(result), 1)

    def test_config_required_fields_present(self) -> None:
        result = load_guardrails(PROJECT_CONFIG)
        for entry in result:
            self.assertTrue(entry.id)
            self.assertTrue(entry.name)
            self.assertIsInstance(entry.level, GuardrailLevel)
            self.assertIsInstance(entry.state, GuardrailState)

    def test_config_ids_unique(self) -> None:
        result = load_guardrails(PROJECT_CONFIG)
        ids = [entry.id for entry in result]
        self.assertEqual(len(ids), len(set(ids)))