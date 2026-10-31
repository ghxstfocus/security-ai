"""Duenn­er HTTP-Client gegen die OpenAI-kompatible DeepSeek-API.

Nur stdlib (``json``, ``urllib.error``, ``urllib.request``). Kein SDK,
kein Streaming. Fehler werden fail closed in ``LLMError``-Subklassen
geworfen.

Konfiguration kommt ausschliesslich ueber den Konstruktor, damit
``harness`` nicht von ``core`` abhaengt. Der API-Key wird bewusst
NICHT aus ``os.environ`` gelesen; ``API_KEY_ENV_HINT`` ist nur ein
Doku-String fuer Aufrufer.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from harness.llm.errors import LLMError, LLMTimeout, LLMUnavailable
from harness.llm.models import (
    DEFAULT_TIMEOUT,
    LLMRequest,
    LLMResponse,
)

DEFAULT_DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEFAULT_DEEPSEEK_MODEL = "deepseek-chat"
CHAT_COMPLETIONS_PATH = "/v1/chat/completions"
MODELS_PATH = "/v1/models"
API_KEY_ENV_HINT = "DEEPSEEK_API_KEY"

__all__ = [
    "API_KEY_ENV_HINT",
    "CHAT_COMPLETIONS_PATH",
    "DEFAULT_DEEPSEEK_BASE_URL",
    "DEFAULT_DEEPSEEK_MODEL",
    "MODELS_PATH",
    "DeepSeekClient",
]


@dataclass(frozen=True)
class DeepSeekClient:
    """Duenner Client gegen die OpenAI-kompatible DeepSeek-API.

    Bewusste Abweichung von ``validate_ollama_base_url``: es gibt keinen
    Loopback-Zwang, weil DeepSeek ein Cloud-Ziel ist. ``base_url`` muss
    dennoch ein nicht-leerer ``str`` sein und mit ``http://`` oder
    ``https://`` beginnen.

    ``api_key`` muss nach ``.strip()`` nicht leer sein, damit nie ein
    unauthentifizierter Request rausgeht und der Fehler frueh und laut
    auftritt.
    """

    base_url: str = DEFAULT_DEEPSEEK_BASE_URL
    api_key: str = ""
    default_model: str = DEFAULT_DEEPSEEK_MODEL
    default_timeout: float = DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        if not isinstance(self.base_url, str) or not self.base_url:
            raise ValueError("base_url muss ein nicht-leerer str sein")
        if not (
            self.base_url.startswith("http://")
            or self.base_url.startswith("https://")
        ):
            raise ValueError(
                "base_url muss mit http:// oder https:// beginnen"
            )
        if not isinstance(self.api_key, str):
            raise ValueError("api_key muss ein str sein")
        if not self.api_key.strip():
            raise ValueError("api_key darf nicht leer sein")
        if not isinstance(self.default_model, str) or not self.default_model:
            raise ValueError("default_model muss ein nicht-leerer str sein")
        if not isinstance(self.default_timeout, (int, float)):
            raise ValueError("default_timeout muss int oder float sein")
        if self.default_timeout <= 0:
            raise ValueError("default_timeout muss > 0 sein")

    def generate(self, request: LLMRequest) -> LLMResponse:
        """Sendet einen Chat-Completion-Request an DeepSeek."""
        if not isinstance(request, LLMRequest):
            raise LLMError(
                f"request muss LLMRequest sein, nicht {type(request).__name__}"
            )

        model = request.model or self.default_model
        timeout = float(request.timeout or self.default_timeout)

        messages: list[dict[str, str]] = []
        if request.system is not None:
            messages.append({"role": "system", "content": request.system})
        messages.append({"role": "user", "content": request.prompt})

        body: dict[str, object] = {
            "model": model,
            "messages": messages,
            "stream": False,
        }
        if request.max_tokens is not None:
            body["max_tokens"] = request.max_tokens

        url = self.base_url.rstrip("/") + CHAT_COMPLETIONS_PATH
        data = json.dumps(body).encode("utf-8")
        http_request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(http_request, timeout=timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise LLMError(
                f"DeepSeek HTTP-Fehler: {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise LLMTimeout("DeepSeek-Request Timeout") from exc
            raise LLMUnavailable(
                f"DeepSeek nicht erreichbar: {exc.reason}"
            ) from exc
        except TimeoutError as exc:
            raise LLMTimeout("DeepSeek-Request Timeout") from exc

        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LLMError("DeepSeek-Antwort ist kein gueltiges JSON") from exc

        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError("DeepSeek-Antwort hat unerwartetes Format") from exc

        return LLMResponse(
            text=content,
            model=payload.get("model", model),
            done=True,
            raw=payload,
        )

    def generate_text(
        self,
        prompt: str,
        *,
        system: str | None = None,
        model: str | None = None,
        max_tokens: int | None = None,
        timeout: float | None = None,
    ) -> str:
        """Kompatibilitaets-Wrapper: liefert nur den Antworttext."""
        # Fix 2026-10-31: LLMRequest validiert streng (model: str,
        # max_tokens > 0, timeout > 0). None-Werte hier nicht
        # durchreichen, sondern Defaults greifen lassen. Live-Beleg:
        # generate_text(prompt) mit model=None -> ValueError.
        kwargs: dict = {"prompt": prompt}
        if system is not None:
            kwargs["system"] = system
        if model is not None:
            kwargs["model"] = model
        if max_tokens is not None:
            kwargs["max_tokens"] = max_tokens
        if timeout is not None:
            kwargs["timeout"] = timeout
        return self.generate(LLMRequest(**kwargs)).text

    def is_available(self, timeout: float | None = None) -> bool:
        """Health-Check gegen ``/v1/models``. Liefert ``True``/``False``."""
        effective_timeout = float(timeout or self.default_timeout)
        url = self.base_url.rstrip("/") + MODELS_PATH
        http_request = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {self.api_key}"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(
                http_request, timeout=effective_timeout
            ) as resp:
                resp.read()
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
            return False
        return True
