"""Tests fuer core/guardrails/loader.py."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.guardrails.loader import (
    GuardrailLoadError,
    load_guardrails,
)
from core.guardrails.models import (
    Guardrail,
    GuardrailLevel,
    GuardrailState,
)


class _TempYamlMixin:
    """Schreibt YAML-Text in eine temporaere Datei."""

    def _write(self, text: str) -> Path:
        # SIM115-Fix (2026-10-16): Context Manager.
        # delete=False, damit die Datei nach dem
        # with-Block erhalten bleibt.
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".yaml",
            delete=False,
            encoding="utf-8",
        ) as tmp:
            tmp.write(text)
        p = Path(tmp.name)
        self.addCleanup(p.unlink, missing_ok=True)
        return p


class LoadGuardrailsSuccessTests(
    _TempYamlMixin, unittest.TestCase
):
    def test_empty_list(self) -> None:
        p = self._write("guardrails: []\n")
        self.assertEqual(load_guardrails(p), [])

    def test_single_entry(self) -> None:
        p = self._write(
            "guardrails:\n"
            "  - id: GR-001\n"
            "    name: Shell blockieren\n"
            "    level: block\n"
            "    state: enabled\n"
        )
        result = load_guardrails(p)
        self.assertEqual(len(result), 1)
        g = result[0]
        self.assertIsInstance(g, Guardrail)
        self.assertEqual(g.id, "GR-001")
        self.assertEqual(g.name, "Shell blockieren")
        self.assertEqual(g.level, GuardrailLevel.BLOCK)
        self.assertEqual(g.state, GuardrailState.ENABLED)

    def test_multiple_entries_order(self) -> None:
        p = self._write(
            "guardrails:\n"
            "  - id: GR-001\n"
            "    name: A\n"
            "    level: info\n"
            "    state: enabled\n"
            "  - id: GR-002\n"
            "    name: B\n"
            "    level: warn\n"
            "    state: disabled\n"
        )
        result = load_guardrails(p)
        self.assertEqual([g.id for g in result], ["GR-001", "GR-002"])

    def test_accepts_str_path(self) -> None:
        p = self._write("guardrails: []\n")
        self.assertEqual(load_guardrails(str(p)), [])

    def test_all_levels(self) -> None:
        p = self._write(
            "guardrails:\n"
            "  - id: GR-001\n"
            "    name: A\n"
            "    level: info\n"
            "    state: enabled\n"
            "  - id: GR-002\n"
            "    name: B\n"
            "    level: warn\n"
            "    state: enabled\n"
            "  - id: GR-003\n"
            "    name: C\n"
            "    level: block\n"
            "    state: enabled\n"
        )
        result = load_guardrails(p)
        self.assertEqual(
            [g.level for g in result],
            [
                GuardrailLevel.INFO,
                GuardrailLevel.WARN,
                GuardrailLevel.BLOCK,
            ],
        )

    def test_all_states(self) -> None:
        p = self._write(
            "guardrails:\n"
            "  - id: GR-001\n"
            "    name: A\n"
            "    level: info\n"
            "    state: enabled\n"
            "  - id: GR-002\n"
            "    name: B\n"
            "    level: info\n"
            "    state: disabled\n"
        )
        result = load_guardrails(p)
        self.assertEqual(
            [g.state for g in result],
            [GuardrailState.ENABLED, GuardrailState.DISABLED],
        )


class LoadGuardrailsIoErrorTests(
    _TempYamlMixin, unittest.TestCase
):
    def test_missing_file(self) -> None:
        with self.assertRaises(GuardrailLoadError):
            load_guardrails("/nonexistent/guardrails.yaml")


class LoadGuardrailsYamlErrorTests(
    _TempYamlMixin, unittest.TestCase
):
    def test_invalid_yaml(self) -> None:
        p = self._write("guardrails: [\n")
        with self.assertRaises(GuardrailLoadError):
            load_guardrails(p)


class LoadGuardrailsStructureTests(
    _TempYamlMixin, unittest.TestCase
):
    def test_empty_file(self) -> None:
        p = self._write("")
        with self.assertRaises(GuardrailLoadError):
            load_guardrails(p)

    def test_top_level_not_mapping(self) -> None:
        p = self._write("- a\n- b\n")
        with self.assertRaises(GuardrailLoadError):
            load_guardrails(p)

    def test_missing_top_level_key(self) -> None:
        p = self._write("other: []\n")
        with self.assertRaises(GuardrailLoadError):
            load_guardrails(p)

    def test_extra_top_level_key(self) -> None:
        p = self._write(
            "guardrails: []\n"
            "extra: 1\n"
        )
        with self.assertRaises(GuardrailLoadError):
            load_guardrails(p)

    def test_top_level_value_not_list(self) -> None:
        p = self._write("guardrails: {}\n")
        with self.assertRaises(GuardrailLoadError):
            load_guardrails(p)

    def test_entry_not_mapping(self) -> None:
        p = self._write(
            "guardrails:\n"
            "  - just-a-string\n"
        )
        with self.assertRaises(GuardrailLoadError):
            load_guardrails(p)

    def test_missing_field(self) -> None:
        p = self._write(
            "guardrails:\n"
            "  - id: GR-001\n"
            "    name: A\n"
            "    level: info\n"
        )
        with self.assertRaises(GuardrailLoadError):
            load_guardrails(p)

    def test_extra_field(self) -> None:
        p = self._write(
            "guardrails:\n"
            "  - id: GR-001\n"
            "    name: A\n"
            "    level: info\n"
            "    state: enabled\n"
            "    extra: 1\n"
        )
        with self.assertRaises(GuardrailLoadError):
            load_guardrails(p)


class LoadGuardrailsValueTests(
    _TempYamlMixin, unittest.TestCase
):
    def test_unknown_level(self) -> None:
        p = self._write(
            "guardrails:\n"
            "  - id: GR-001\n"
            "    name: A\n"
            "    level: critical\n"
            "    state: enabled\n"
        )
        with self.assertRaises(GuardrailLoadError):
            load_guardrails(p)

    def test_unknown_state(self) -> None:
        p = self._write(
            "guardrails:\n"
            "  - id: GR-001\n"
            "    name: A\n"
            "    level: info\n"
            "    state: paused\n"
        )
        with self.assertRaises(GuardrailLoadError):
            load_guardrails(p)

    def test_empty_id(self) -> None:
        p = self._write(
            "guardrails:\n"
            "  - id: ''\n"
            "    name: A\n"
            "    level: info\n"
            "    state: enabled\n"
        )
        with self.assertRaises(GuardrailLoadError):
            load_guardrails(p)

    def test_empty_name(self) -> None:
        p = self._write(
            "guardrails:\n"
            "  - id: GR-001\n"
            "    name: ''\n"
            "    level: info\n"
            "    state: enabled\n"
        )
        with self.assertRaises(GuardrailLoadError):
            load_guardrails(p)

    def test_id_not_string(self) -> None:
        p = self._write(
            "guardrails:\n"
            "  - id: 1\n"
            "    name: A\n"
            "    level: info\n"
            "    state: enabled\n"
        )
        with self.assertRaises(GuardrailLoadError):
            load_guardrails(p)

    def test_level_not_string(self) -> None:
        p = self._write(
            "guardrails:\n"
            "  - id: GR-001\n"
            "    name: A\n"
            "    level: 1\n"
            "    state: enabled\n"
        )
        with self.assertRaises(GuardrailLoadError):
            load_guardrails(p)