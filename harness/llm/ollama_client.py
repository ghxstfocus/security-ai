# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
DEPRECATED: Verwende harness.llm.client.

Diese Datei bleibt als Re-Export-Fassade, damit bestehende Imports
(z. B. in scripts/chat_cli.py) bis zur Umstellung weiterlaufen.

Entfernung: eigener Commit, sobald alle Aufrufer und Tests auf
harness.llm.client umgestellt sind.
"""
from __future__ import annotations

from harness.llm.client import (
    DEFAULT_BASE_URL,
    OllamaClient,
)
from harness.llm.errors import (
    LLMError,
    LLMTimeout,
    LLMUnavailable,
)
from harness.llm.models import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_MODEL,
    DEFAULT_TIMEOUT,
    LLMRequest,
    LLMResponse,
)

__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_MAX_TOKENS",
    "DEFAULT_MODEL",
    "DEFAULT_TIMEOUT",
    "LLMError",
    "LLMRequest",
    "LLMResponse",
    "LLMTimeout",
    "LLMUnavailable",
    "OllamaClient",
]
