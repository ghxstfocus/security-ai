"""Spec: harness/llm/deepseek_client.py (DeepSeekClient).

Alle Aufrufe von urllib.request.urlopen sind gemockt.
Kein echtes Netz, kein DeepSeek-Key noetig.

Spec-Grund: ersetzt tests/unit/test_llm_client.py (OllamaClient),
2026-10-31 geloescht. DeepSeekClient ist der Nachfolger.
"""
from __future__ import annotations

import json
import unittest
import urllib.error
from unittest import mock

from harness.llm.deepseek_client import (
    CHAT_COMPLETIONS_PATH,
    DEFAULT_DEEPSEEK_BASE_URL,
    DEFAULT_DEEPSEEK_MODEL,
    MODELS_PATH,
    DeepSeekClient,
)
from harness.llm.errors import LLMError, LLMTimeout, LLMUnavailable
from harness.llm.models import LLMRequest


class _FakeResp:
    def __init__(self, payload, status: int = 200) -> None:
        self._body = json.dumps(payload).encode("utf-8")
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _BadJsonResp:
    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    def read(self) -> bytes:
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _ok_payload(text: str = "hallo", model: str = "deepseek-chat") -> dict:
    return {
        "id": "chatcmpl-1",
        "model": model,
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": text}}
        ],
    }


# ---------------------------------------------------------------------- #
# Konstruktor
# ---------------------------------------------------------------------- #

class DeepSeekClientConstructorTests(unittest.TestCase):
    def test_defaults(self):
        c = DeepSeekClient(api_key="sk-x")
        self.assertEqual(c.base_url, DEFAULT_DEEPSEEK_BASE_URL)
        self.assertEqual(c.default_model, DEFAULT_DEEPSEEK_MODEL)
        self.assertGreater(c.default_timeout, 0)
        self.assertEqual(c.api_key, "sk-x")

    def test_custom(self):
        c = DeepSeekClient(
            base_url="https://proxy.example.com",
            api_key="sk-y",
            default_model="deepseek-reasoner",
            default_timeout=60.0,
        )
        self.assertEqual(c.base_url, "https://proxy.example.com")
        self.assertEqual(c.default_model, "deepseek-reasoner")
        self.assertEqual(c.default_timeout, 60.0)

    def test_ungueltige_werte(self):
        for bad in [
            {"api_key": ""},
            {"api_key": "   "},
            {"base_url": ""},
            {"base_url": "ftp://x"},
            {"default_model": ""},
            {"default_timeout": 0},
            {"default_timeout": -1},
        ]:
            with self.assertRaises(ValueError, msg=bad):
                DeepSeekClient(**bad)


# ---------------------------------------------------------------------- #
# generate
# ---------------------------------------------------------------------- #

class DeepSeekClientGenerateTests(unittest.TestCase):
    def setUp(self):
        self.c = DeepSeekClient(api_key="sk-test")

    def _call(self, payload: dict | None = None, **req_kw):
        req = LLMRequest(prompt="hi", **req_kw)
        resp = _FakeResp(payload or _ok_payload())
        with mock.patch("urllib.request.urlopen", return_value=resp) as m:
            result = self.c.generate(req)
        return result, m

    def test_happy_path(self):
        result, _ = self._call()
        self.assertEqual(result.text, "hallo")
        self.assertEqual(result.model, "deepseek-chat")
        self.assertTrue(result.done)

    def test_authorization_header(self):
        _, m = self._call()
        http_request = m.call_args[0][0]
        self.assertEqual(
            http_request.get_header("Authorization"), "Bearer sk-test"
        )

    def test_url_enthaelt_chat_completions_path(self):
        _, m = self._call()
        http_request = m.call_args[0][0]
        self.assertTrue(http_request.full_url.endswith(CHAT_COMPLETIONS_PATH))

    def test_request_model_gewinnt(self):
        _, m = self._call(model="deepseek-reasoner")
        body = json.loads(m.call_args[0][0].data.decode("utf-8"))
        self.assertEqual(body["model"], "deepseek-reasoner")

    def test_system_landet_in_messages(self):
        _, m = self._call(system="du bist X")
        body = json.loads(m.call_args[0][0].data.decode("utf-8"))
        self.assertEqual(body["messages"][0],
                         {"role": "system", "content": "du bist X"})
        self.assertEqual(body["messages"][1],
                         {"role": "user", "content": "hi"})

    def test_kein_system_nur_user(self):
        _, m = self._call()
        body = json.loads(m.call_args[0][0].data.decode("utf-8"))
        self.assertEqual(len(body["messages"]), 1)
        self.assertEqual(body["messages"][0]["role"], "user")

    def test_max_tokens_durchgereicht(self):
        _, m = self._call(max_tokens=42)
        body = json.loads(m.call_args[0][0].data.decode("utf-8"))
        self.assertEqual(body["max_tokens"], 42)

    def test_default_max_tokens_landet_im_body(self):
        # Spec: LLMRequest.max_tokens ist Pflichtfeld (Default 512,
        # Validierung > 0). None ist nicht erlaubt -> max_tokens
        # landet immer im Body, entweder explizit oder als Default.
        from harness.llm.models import DEFAULT_MAX_TOKENS
        _, m = self._call()
        body = json.loads(m.call_args[0][0].data.decode("utf-8"))
        self.assertEqual(body["max_tokens"], DEFAULT_MAX_TOKENS)

    def test_nicht_llm_request_wirft(self):
        with self.assertRaises(LLMError):
            self.c.generate({"prompt": "x"})  # type: ignore[arg-type]

    def test_httperror_wirft_llmerror(self):
        err = urllib.error.HTTPError(
            "http://x", 401, "unauthorized", {}, None  # type: ignore[arg-type]
        )
        with mock.patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(LLMError):
                self.c.generate(LLMRequest(prompt="hi"))

    def test_urlerror_timeout_wirft_llmtimeout(self):
        err = urllib.error.URLError(TimeoutError())
        with mock.patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(LLMTimeout):
                self.c.generate(LLMRequest(prompt="hi"))

    def test_urlerror_sonst_wirft_llmunavailable(self):
        err = urllib.error.URLError("network down")
        with mock.patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(LLMUnavailable):
                self.c.generate(LLMRequest(prompt="hi"))

    def test_timeout_wirft_llmtimeout(self):
        with mock.patch("urllib.request.urlopen", side_effect=TimeoutError()):
            with self.assertRaises(LLMTimeout):
                self.c.generate(LLMRequest(prompt="hi"))

    def test_kaputtes_json_wirft_llmerror(self):
        resp = _BadJsonResp(b"not json {")
        with mock.patch("urllib.request.urlopen", return_value=resp):
            with self.assertRaises(LLMError):
                self.c.generate(LLMRequest(prompt="hi"))

    def test_fehlendes_choices_wirft_llmerror(self):
        resp = _FakeResp({"id": "x", "model": "m"})
        with mock.patch("urllib.request.urlopen", return_value=resp):
            with self.assertRaises(LLMError):
                self.c.generate(LLMRequest(prompt="hi"))

    def test_leere_choices_wirft_llmerror(self):
        resp = _FakeResp({"choices": []})
        with mock.patch("urllib.request.urlopen", return_value=resp):
            with self.assertRaises(LLMError):
                self.c.generate(LLMRequest(prompt="hi"))


# ---------------------------------------------------------------------- #
# generate_text
# ---------------------------------------------------------------------- #

class DeepSeekClientGenerateTextTests(unittest.TestCase):
    def test_convenience_liefert_str(self):
        c = DeepSeekClient(api_key="sk-x")
        resp = _FakeResp(_ok_payload("antwort"))
        with mock.patch("urllib.request.urlopen", return_value=resp):
            out = c.generate_text("frage", system="sys")
        self.assertEqual(out, "antwort")


# ---------------------------------------------------------------------- #
# is_available
# ---------------------------------------------------------------------- #

class DeepSeekClientAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.c = DeepSeekClient(api_key="sk-x")

    def test_available_true(self):
        resp = _FakeResp({"data": []})
        with mock.patch("urllib.request.urlopen", return_value=resp):
            self.assertTrue(self.c.is_available())

    def test_available_false_bei_httperror(self):
        err = urllib.error.HTTPError(
            "http://x", 500, "err", {}, None  # type: ignore[arg-type]
        )
        with mock.patch("urllib.request.urlopen", side_effect=err):
            self.assertFalse(self.c.is_available())

    def test_available_false_bei_urlerror(self):
        err = urllib.error.URLError("down")
        with mock.patch("urllib.request.urlopen", side_effect=err):
            self.assertFalse(self.c.is_available())

    def test_available_false_bei_timeout(self):
        with mock.patch("urllib.request.urlopen", side_effect=TimeoutError()):
            self.assertFalse(self.c.is_available())

    def test_url_enthaelt_models_path(self):
        resp = _FakeResp({"data": []})
        with mock.patch("urllib.request.urlopen", return_value=resp) as m:
            self.c.is_available()
        http_request = m.call_args[0][0]
        self.assertTrue(http_request.full_url.endswith(MODELS_PATH))
