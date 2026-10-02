# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
LLM-Datenmodelle.

LLMRequest  — Eingabe an den Client.
LLMResponse — Ausgabe vom Client.

Beide sind frozen dataclasses (unveraenderlich), damit Requests
und Responses gefahrlos durch Service-Schichten gereicht werden
koennen.

Konventionen:
- max_tokens > 0, timeout > 0 (fail closed).
- model als String, keine Pruefung gegen eine Liste (Ollama
  lehnt unbekannte Modelle selbst ab).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

DEFAULT_MODEL = "llama3.2:3b"
DEFAULT_MAX_TOKENS = 512
DEFAULT_TIMEOUT = 30.0


@dataclass(frozen=True)
class LLMRequest:
    """Eine Anfrage an ein LLM."""

    prompt: str
    system: str | None = None
    model: str = DEFAULT_MODEL
    max_tokens: int = DEFAULT_MAX_TOKENS
    timeout: float = DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        if not isinstance(self.prompt, str) or not self.prompt.strip():
            raise ValueError("LLMRequest.prompt darf nicht leer sein")
        if self.system is not None and not isinstance(self.system, str):
            raise ValueError(
                "LLMRequest.system muss String oder None sein"
            )
        if not isinstance(self.model, str) or not self.model.strip():
            raise ValueError("LLMRequest.model darf nicht leer sein")
        if not isinstance(self.max_tokens, int) or self.max_tokens <= 0:
            raise ValueError("LLMRequest.max_tokens muss > 0 sein")
        if not isinstance(self.timeout, (int, float)) \
                or self.timeout <= 0:
            raise ValueError("LLMRequest.timeout muss > 0 sein")


@dataclass(frozen=True)
class LLMResponse:
    """Eine Antwort von einem LLM."""

    text: str
    model: str
    done: bool = True
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.text, str):
            raise TypeError("LLMResponse.text muss String sein")
        if not isinstance(self.model, str):
            raise TypeError("LLMResponse.model muss String sein")
        if not self.model:
            raise ValueError("LLMResponse.model darf nicht leer sein")
        if not isinstance(self.done, bool):
            raise TypeError("LLMResponse.done muss bool sein")
        if not isinstance(self.raw, dict):
            raise TypeError("LLMResponse.raw muss dict sein")


__all__ = [
    "DEFAULT_MAX_TOKENS",
    "DEFAULT_MODEL",
    "DEFAULT_TIMEOUT",
    "LLMRequest",
    "LLMResponse",
]
