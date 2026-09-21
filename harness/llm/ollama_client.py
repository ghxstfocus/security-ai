"""
Ollama-Client.

Ruft die lokale Ollama-HTTP-API auf. Kein Cloud-Zugriff.

Design:
- Synchron, kein Streaming (erstmal).
- Fail closed: Ollama nicht erreichbar -> LLMError.
- Timeout explizit, Default 30 s.
- Kein Shell, keine externen Prozesse.
- Testbar ohne Ollama: Mock oder Fake.

API:
    POST http://127.0.0.1:11434/api/generate
    Body: {"model": ..., "prompt": ..., "system": ..., "stream": false}
    Antwort-JSON: {"response": "...", "done": true, ...}
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


DEFAULT_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen2.5:7b"
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_TOKENS = 512


class LLMError(RuntimeError):
    """Ollama nicht erreichbar, Zeitueberschreitung, oder Formatfehler."""


@dataclass(frozen=True)
class OllamaClient:
    """
    Duenner HTTP-Client fuer Ollama.

    base_url: z. B. http://127.0.0.1:11434
    model:    z. B. qwen2.5:7b
    """

    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    timeout: float = DEFAULT_TIMEOUT
    max_tokens: int = DEFAULT_MAX_TOKENS

    def __post_init__(self) -> None:
        if not isinstance(self.base_url, str) or not self.base_url:
            raise ValueError("base_url darf nicht leer sein")
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError(
                "base_url muss mit http:// oder https:// beginnen"
            )
        if not isinstance(self.model, str) or not self.model:
            raise ValueError("model darf nicht leer sein")
        if not isinstance(self.timeout, (int, float)) or self.timeout <= 0:
            raise ValueError("timeout muss > 0 sein")
        if not isinstance(self.max_tokens, int) or self.max_tokens <= 0:
            raise ValueError("max_tokens muss > 0 sein")

    # ------------------------------------------------------------------ #
    # API
    # ------------------------------------------------------------------ #

    def generate(
        self,
        *,
        prompt: str,
        system: str | None = None,
        max_tokens: int | None = None,
        timeout: float | None = None,
    ) -> str:
        """
        Ruft /api/generate auf. Liefert den Antwort-Text.

        Fail closed: jeder Fehler -> LLMError.
        """
        if not isinstance(prompt, str) or not prompt:
            raise LLMError("prompt darf nicht leer sein")
        if system is not None and not isinstance(system, str):
            raise LLMError("system muss String oder None sein")

        effective_timeout = float(
            timeout if timeout is not None else self.timeout
        )
        if effective_timeout <= 0:
            raise LLMError("timeout muss > 0 sein")

        effective_max = int(
            max_tokens if max_tokens is not None else self.max_tokens
        )
        if effective_max <= 0:
            raise LLMError("max_tokens muss > 0 sein")

        body: dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": effective_max},
        }
        if system is not None:
            body["system"] = system

        url = self.base_url.rstrip("/") + "/api/generate"
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                req, timeout=effective_timeout
            ) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise LLMError(
                f"Ollama HTTP {exc.code}: {exc.reason}"
            ) from exc
        except urllib.error.URLError as exc:
            raise LLMError(
                f"Ollama nicht erreichbar: {exc.reason}"
            ) from exc
        except TimeoutError as exc:
            raise LLMError(
                f"Ollama Timeout nach {effective_timeout}s"
            ) from exc
        except OSError as exc:
            raise LLMError(f"Ollama OSError: {exc}") from exc

        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LLMError(
                f"Ollama-Antwort nicht parsebar: {exc}"
            ) from exc

        if not isinstance(payload, dict):
            raise LLMError(
                f"Ollama-Antwort ist kein Objekt: {type(payload).__name__}"
            )
        response = payload.get("response")
        if not isinstance(response, str):
            raise LLMError("Ollama-Antwort ohne 'response'-Feld")

        return response

    # ------------------------------------------------------------------ #
    # Health-Check
    # ------------------------------------------------------------------ #

    def is_available(self, timeout: float = 2.0) -> bool:
        """True, wenn /api/tags erreichbar ist. Kein raise."""
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            return False
        url = self.base_url.rstrip("/") + "/api/tags"
        try:
            with urllib.request.urlopen(url, timeout=float(timeout)) as r:
                return r.status == 200
        except Exception:
            return False


__all__ = [
    "OllamaClient",
    "LLMError",
    "DEFAULT_BASE_URL",
    "DEFAULT_MODEL",
    "DEFAULT_TIMEOUT",
    "DEFAULT_MAX_TOKENS",
]
