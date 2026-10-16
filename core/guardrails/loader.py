"""YAML-Loader fuer Guardrails (Phase 5).

Laedt eine Guardrail-Datei und liefert eine Liste von
Guardrail-Objekten. Fail closed bei jedem Fehler:
IO, YAML-Syntax, Struktur, Werte.

Schema (verbindlich):

    guardrails:
      - id: GR-001
        name: "Shell-Zugriff blockieren"
        level: block
        state: enabled

Top-Level: Mapping mit genau dem Schluessel "guardrails".
Wert: Liste von Mappings.
Pflichtfelder pro Eintrag: id, name, level, state.
level: info | warn | block
state: enabled | disabled
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from core.guardrails.models import (
    Guardrail,
    GuardrailLevel,
    GuardrailState,
)

TOP_LEVEL_KEY = "guardrails"
REQUIRED_FIELDS = ("id", "name", "level", "state")


class GuardrailLoadError(Exception):
    """Fehler beim Laden einer Guardrail-Datei."""


def _require_mapping(value: Any, where: str) -> dict:
    if not isinstance(value, dict):
        raise GuardrailLoadError(
            f"{where}: Mapping erwartet, "
            f"erhalten {type(value).__name__}"
        )
    return value


def _require_str(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise GuardrailLoadError(
            f"{where}: nicht-leerer String erwartet"
        )
    return value


def _parse_level(value: Any, where: str) -> GuardrailLevel:
    raw = _require_str(value, where)
    try:
        return GuardrailLevel(raw)
    except ValueError as exc:
        allowed = ", ".join(m.value for m in GuardrailLevel)
        raise GuardrailLoadError(
            f"{where}: unbekannter level {raw!r} "
            f"(erlaubt: {allowed})"
        ) from exc


def _parse_state(value: Any, where: str) -> GuardrailState:
    raw = _require_str(value, where)
    try:
        return GuardrailState(raw)
    except ValueError as exc:
        allowed = ", ".join(m.value for m in GuardrailState)
        raise GuardrailLoadError(
            f"{where}: unbekannter state {raw!r} "
            f"(erlaubt: {allowed})"
        ) from exc


def _parse_entry(raw: Any, index: int) -> Guardrail:
    where = f"{TOP_LEVEL_KEY}[{index}]"
    entry = _require_mapping(raw, where)

    missing = [f for f in REQUIRED_FIELDS if f not in entry]
    if missing:
        raise GuardrailLoadError(
            f"{where}: Pflichtfelder fehlen: "
            f"{', '.join(missing)}"
        )

    extra = [k for k in entry if k not in REQUIRED_FIELDS]
    if extra:
        raise GuardrailLoadError(
            f"{where}: unbekannte Felder: "
            f"{', '.join(sorted(extra))}"
        )

    gid = _require_str(entry["id"], f"{where}.id")
    name = _require_str(entry["name"], f"{where}.name")
    level = _parse_level(entry["level"], f"{where}.level")
    state = _parse_state(entry["state"], f"{where}.state")

    return Guardrail(id=gid, name=name, level=level, state=state)


def load_guardrails(path: str | Path) -> list[Guardrail]:
    """Laedt Guardrails aus einer YAML-Datei.

    Fail closed: jeder Fehler (IO, YAML, Struktur, Werte)
    fuehrt zu GuardrailLoadError.
    """
    p = Path(path)

    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise GuardrailLoadError(
            f"{p}: Datei nicht lesbar: {exc}"
        ) from exc

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise GuardrailLoadError(
            f"{p}: YAML-Syntaxfehler: {exc}"
        ) from exc

    root = _require_mapping(data, str(p))

    if TOP_LEVEL_KEY not in root:
        raise GuardrailLoadError(
            f"{p}: Top-Level-Schluessel "
            f"{TOP_LEVEL_KEY!r} fehlt"
        )

    extra_top = [k for k in root if k != TOP_LEVEL_KEY]
    if extra_top:
        raise GuardrailLoadError(
            f"{p}: unbekannte Top-Level-Schluessel: "
            f"{', '.join(sorted(extra_top))}"
        )

    entries = root[TOP_LEVEL_KEY]
    if not isinstance(entries, list):
        raise GuardrailLoadError(
            f"{p}: {TOP_LEVEL_KEY!r} muss eine Liste sein"
        )

    return [_parse_entry(e, i) for i, e in enumerate(entries)]