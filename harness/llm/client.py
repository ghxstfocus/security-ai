"""
Ollama-Client.

Ruft die lokale Ollama-HTTP-API auf. Kein Cloud-Zugriff.

Design:
- Synchron, kein Streaming.
- Client bleibt dumm: Modell und Timeout sind Parameter.
  Defaults kommen aus harness.llm.models.
- Fail closed:
    HTTP != 2xx         -> LLMError
    nicht erreichbar    -> LLMUnavailable
    Timeout             -> LLMTimeout
    kaputtes JSON       -> LLMError
- Kein Shell, keine externen Prozesse. Nur urllib.

API:
    POST <base_url>/api/generate
    Body: {"model": ..., "prompt": ..., "system": ..., "stream": false,
           "options": {"num_predict": ...}}
    Antwort-JSON: {"response": "...", "done": true, "model": "...", ...}
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from harness.llm.errors import LLMError, LLMTimeout, LLMUnavailable
from harness.llm.models import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_MODEL,
    DEFAULT_TIMEOUT,
    LLMRequest,
    LLMResponse,
)

DEFAULT_BASE_URL = "http://127.0.0.1:11434"


@dataclass(frozen=True)
class OllamaClient:
    """
    Duenner HTTP-Client fuer Ollama.

    base_url:        z. B. http://127.0.0.1:11434
    default_model:   Modell, wenn LLMRequest.model nicht gesetzt ist
    default_timeout: Timeout in s, wenn LLMRequest.timeout nicht
                     gesetzt ist
    """

    base_url: str = DEFAULT_BASE_URL
    default_model: str = DEFAULT_MODEL
    default_timeout: float = DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        if not isinstance(self.base_url, str) or not self.base_url:
            raise ValueError("base_url darf nicht leer sein")
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError(
                "base_url muss mit http:// oder https:// beginnen"
            )
        if not isinstance(self.default_model, str) \
                or not self.default_model:
            raise ValueError("default_model darf nicht leer sein")
        if not isinstance(self.default_timeout, (int, float)) \
                or self.default_timeout <= 0:
            raise ValueError("default_timeout muss > 0 sein")

    # ------------------------------------------------------------------ #
    # oeffentliche API
    # ------------------------------------------------------------------ #

    def generate(self, request: LLMRequest) -> LLMResponse:
        """
        Fuehrt eine LLM-Anfrage aus.

        Fail closed: jeder Fehler -> eine LLMError-Subklasse.
        """
        if not isinstance(request, LLMRequest):
            raise LLMError(
                f"request muss LLMRequest sein, "
                f"nicht {type(request).__name__}"
            )

        model = request.model or self.default_model
        timeout = float(request.timeout or self.default_timeout)

        body: dict = {
            "model": model,
            "prompt": request.prompt,
            "stream": False,
            "options": {"num_predict": request.max_tokens},
        }
        if request.system is not None:
            body["system"] = request.system

        url = self.base_url.rstrip("/") + "/api/generate"
        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise LLMError(
                f"Ollama HTTP {exc.code}: {exc.reason}"
            ) from exc
        except urllib.error.URLError as exc:
            raise LLMUnavailable(
                f"Ollama nicht erreichbar: {exc.reason}"
            ) from exc
        except TimeoutError as exc:
            raise LLMTimeout(
                f"Ollama Timeout nach {timeout}s"
            ) from exc
        except ConnectionError as exc:
            raise LLMUnavailable(
                f"Ollama Verbindungsfehler: {exc}"
            ) from exc
        except OSError as exc:
            raise LLMError(f"Ollama OSError: {exc}") from exc

        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LLMError(
                f"Ollama-Antwort nicht parsebar: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise LLMError(
                f"Ollama-Antwort ist kein Objekt: {type(data).__name__}"
            )
        text = data.get("response")
        if not isinstance(text, str):
            raise LLMError("Ollama-Antwort ohne 'response'-Feld")

        return LLMResponse(
            text=text,
            model=str(data.get("model") or model),
            done=bool(data.get("done", True)),
            raw=data,
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
        """
        Convenience-Wrapper. Liefert nur den Antwort-Text.
        Fuer Aufrufer, die LLMResponse nicht brauchen (ChatService).
        """
        req = LLMRequest(
            prompt=prompt,
            system=system,
            model=model or self.default_model,
            max_tokens=max_tokens or DEFAULT_MAX_TOKENS,
            timeout=timeout or self.default_timeout,
        )
        return self.generate(req).text

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
    "DEFAULT_BASE_URL",
    "OllamaClient",
]
