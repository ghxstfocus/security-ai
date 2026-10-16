"""Tests fuer core/guardrails/models.py."""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from core.guardrails.models import (
    Guardrail,
    GuardrailLevel,
    GuardrailState,
)


class GuardrailLevelTests(unittest.TestCase):
    def test_level_values(self) -> None:
        self.assertEqual(GuardrailLevel.INFO.value, "info")
        self.assertEqual(GuardrailLevel.WARN.value, "warn")
        self.assertEqual(GuardrailLevel.BLOCK.value, "block")

    def test_level_is_str_enum(self) -> None:
        self.assertIsInstance(GuardrailLevel.INFO, str)
        self.assertEqual(GuardrailLevel.INFO, "info")

    def test_level_members(self) -> None:
        self.assertEqual(
            set(GuardrailLevel.__members__),
            {"INFO", "WARN", "BLOCK"},
        )


class GuardrailStateTests(unittest.TestCase):
    def test_state_values(self) -> None:
        self.assertEqual(GuardrailState.ENABLED.value, "enabled")
        self.assertEqual(GuardrailState.DISABLED.value, "disabled")

    def test_state_is_str_enum(self) -> None:
        self.assertIsInstance(GuardrailState.ENABLED, str)
        self.assertEqual(GuardrailState.ENABLED, "enabled")

    def test_state_members(self) -> None:
        self.assertEqual(
            set(GuardrailState.__members__),
            {"ENABLED", "DISABLED"},
        )


class GuardrailTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        g = Guardrail(
            id="GR-001",
            name="Shell-Zugriff blockieren",
            level=GuardrailLevel.BLOCK,
            state=GuardrailState.ENABLED,
        )
        self.assertEqual(g.id, "GR-001")
        self.assertEqual(g.name, "Shell-Zugriff blockieren")
        self.assertEqual(g.level, GuardrailLevel.BLOCK)
        self.assertEqual(g.state, GuardrailState.ENABLED)

    def test_field_order(self) -> None:
        fields = [f.name for f in Guardrail.__dataclass_fields__.values()]
        self.assertEqual(fields, ["id", "name", "level", "state"])

    def test_exactly_four_fields(self) -> None:
        self.assertEqual(len(Guardrail.__dataclass_fields__), 4)

    def test_frozen_assignment_raises(self) -> None:
        g = Guardrail(
            id="GR-002",
            name="Test",
            level=GuardrailLevel.INFO,
            state=GuardrailState.DISABLED,
        )
        with self.assertRaises(FrozenInstanceError):
            g.id = "GR-003"  # type: ignore[misc]

    def test_frozen_state_assignment_raises(self) -> None:
        g = Guardrail(
            id="GR-004",
            name="Test",
            level=GuardrailLevel.WARN,
            state=GuardrailState.ENABLED,
        )
        with self.assertRaises(FrozenInstanceError):
            g.state = GuardrailState.DISABLED  # type: ignore[misc]

    def test_equality(self) -> None:
        a = Guardrail(
            id="GR-005",
            name="A",
            level=GuardrailLevel.INFO,
            state=GuardrailState.ENABLED,
        )
        b = Guardrail(
            id="GR-005",
            name="A",
            level=GuardrailLevel.INFO,
            state=GuardrailState.ENABLED,
        )
        self.assertEqual(a, b)

    def test_inequality(self) -> None:
        a = Guardrail(
            id="GR-006",
            name="A",
            level=GuardrailLevel.INFO,
            state=GuardrailState.ENABLED,
        )
        b = Guardrail(
            id="GR-006",
            name="B",
            level=GuardrailLevel.INFO,
            state=GuardrailState.ENABLED,
        )
        self.assertNotEqual(a, b)