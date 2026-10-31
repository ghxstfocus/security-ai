# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
LLM-Fehlerklassen.

Hierarchie:
    LLMError                (Basis)
      LLMUnavailable        (DeepSeek nicht erreichbar)
      LLMTimeout            (Zeitueberschreitung)

Aufrufer koennen:
- LLMError fangen (alles),
- oder gezielt LLMUnavailable/LLMTimeout.

Fail closed: jeder Fehler beim LLM-Aufruf fuehrt zu einer dieser
Klassen. Kein stiller Fallback im Client.
"""
from __future__ import annotations


class LLMError(RuntimeError):
    """Basisklasse fuer LLM-Fehler."""


class LLMUnavailable(LLMError):
    """DeepSeek ist nicht erreichbar (Connection refused, DNS, ...)."""


class LLMTimeout(LLMError):
    """DeepSeek hat nicht rechtzeitig geantwortet."""


__all__ = [
    "LLMError",
    "LLMTimeout",
    "LLMUnavailable",
]
