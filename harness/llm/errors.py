"""
LLM-Fehlerklassen.

Hierarchie:
    LLMError                (Basis)
      LLMUnavailable        (Ollama nicht erreichbar)
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
    """Ollama ist nicht erreichbar (Connection refused, DNS, ...)."""


class LLMTimeout(LLMError):
    """Ollama hat nicht rechtzeitig geantwortet."""


__all__ = [
    "LLMError",
    "LLMUnavailable",
    "LLMTimeout",
]
