"""
Tests fuer harness/llm/client.py (OllamaClient).

Alle Aufrufe von urllib.request.urlopen werden gemockt.
Kein echtes Netz, kein Ollama noetig.
"""
from __future__ import annotations

import json
import unittest
import urllib.error
from unittest import mock

from harness.llm.client import DEFAULT_BASE_URL, OllamaClient
from harness.llm.errors import LLMError, LLMTimeout, LLMUnavailable
from harness.llm.models import (
    DEFAULT_MODEL,
    LLMRequest,
    LLMResponse,
)

# ---------------------------------------------------------------------- #
# Fake-Response
# ---------------------------------------------------------------------- #

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
    def __init__(self, body: bytes = b"kein json") -> None:
        self._body = body
        self.status = 200

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ---------------------------------------------------------------------- #
# Konstruktor
# ---------------------------------------------------------------------- #

class OllamaClientConstructorTests(unittest.TestCase):
    def test_defaults(self):
        c = OllamaClient()
        self.assertEqual(c.base_url, DEFAULT_BASE_URL)
        self.assertEqual(c.default_model, DEFAULT_MODEL)
        self.assertGreater(c.default_timeout, 0)

    def test_custom(self):
        c = OllamaClient(
            base_url="http://10.0.0.1:1234",
            default_model="qwen2.5:7b",
            default_timeout=60.0,
        )
        self.assertEqual(c.base_url, "http://10.0.0.1:1234")
        self.assertEqual(c.default_model, "qwen2.5:7b")

    def test_ungueltige_werte(self):
        for bad in [
            dict(base_url=""),
            dict(base_url="ftp://x"),
            dict(default_model=""),
            dict(default_timeout=0),
            dict(default_timeout=-1),
        ]:
            with self.assertRaises(ValueError, msg=bad):
                OllamaClient(**bad)


# ---------------------------------------------------------------------- #
# generate
# ---------------------------------------------------------------------- #

class OllamaClientGenerateTests(unittest.TestCase):
    def setUp(self):
        self.c = OllamaClient()

    def test_happy_path(self):
        with mock.patch(
            "urllib.request.urlopen",
            return_value=_FakeResp({
                "response": "Hallo Welt",
                "done": True,
                "model": "llama3.2:3b",
            }),
        ):
            r = self.c.generate(LLMRequest(prompt="hi"))
        self.assertIsInstance(r, LLMResponse)
        self.assertEqual(r.text, "Hallo Welt")
        self.assertEqual(r.model, "llama3.2:3b")
        self.assertTrue(r.done)
        self.assertIn("response", r.raw)

    def test_generate_text_convenience(self):
        with mock.patch(
            "urllib.request.urlopen",
            return_value=_FakeResp({"response": "Servus"}),
        ):
            out = self.c.generate_text("hi", model="qwen2.5:7b")
        self.assertEqual(out, "Servus")

    def test_request_model_gewinnt(self):
        captured = {}

        def _fake(req, timeout):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return _FakeResp({"response": "x"})

        with mock.patch("urllib.request.urlopen", side_effect=_fake):
            self.c.generate(LLMRequest(prompt="hi", model="qwen2.5:7b"))
        self.assertEqual(captured["body"]["model"], "qwen2.5:7b")
        self.assertFalse(captured["body"]["stream"])
        self.assertIn("num_predict", captured["body"]["options"])

    def test_system_landet_im_body(self):
        captured = {}

        def _fake(req, timeout):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return _FakeResp({"response": "x"})

        with mock.patch("urllib.request.urlopen", side_effect=_fake):
            self.c.generate(LLMRequest(prompt="hi", system="Du bist Bot"))
        self.assertEqual(captured["body"]["system"], "Du bist Bot")

    def test_kein_system_kein_feld(self):
        captured = {}

        def _fake(req, timeout):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return _FakeResp({"response": "x"})

        with mock.patch("urllib.request.urlopen", side_effect=_fake):
            self.c.generate(LLMRequest(prompt="hi"))
        self.assertNotIn("system", captured["body"])

    def test_nicht_llm_request_wirft_llmerror(self):
        with self.assertRaises(LLMError):
            self.c.generate("kein request")

    # ------------------------------------------------------------------ #
    # Fehler
    # ------------------------------------------------------------------ #

    def test_httperror_wirft_llmerror(self):
        def _raise(req, timeout):
            raise urllib.error.HTTPError(
                "u", 500, "Server Error", {}, None
            )
        with mock.patch("urllib.request.urlopen", side_effect=_raise):
            with self.assertRaises(LLMError) as cm:
                self.c.generate(LLMRequest(prompt="x"))
        self.assertNotIsInstance(cm.exception, LLMUnavailable)
        self.assertNotIsInstance(cm.exception, LLMTimeout)
        self.assertIn("500", str(cm.exception))

    def test_urlerror_wirft_llmunavailable(self):
        def _raise(req, timeout):
            raise urllib.error.URLError("refused")
        with mock.patch("urllib.request.urlopen", side_effect=_raise):
            with self.assertRaises(LLMUnavailable):
                self.c.generate(LLMRequest(prompt="x"))

    def test_connectionerror_wirft_llmunavailable(self):
        with mock.patch(
            "urllib.request.urlopen",
            side_effect=ConnectionError("refused"),
        ):
            with self.assertRaises(LLMUnavailable):
                self.c.generate(LLMRequest(prompt="x"))

    def test_timeout_wirft_llmtimeout(self):
        with mock.patch(
            "urllib.request.urlopen",
            side_effect=TimeoutError("x"),
        ):
            with self.assertRaises(LLMTimeout):
                self.c.generate(LLMRequest(prompt="x", timeout=1.0))

    def test_oserror_wirft_llmerror(self):
        with mock.patch(
            "urllib.request.urlopen",
            side_effect=OSError("sonstiger fehler"),
        ):
            with self.assertRaises(LLMError) as cm:
                self.c.generate(LLMRequest(prompt="x"))
        self.assertNotIsInstance(cm.exception, (LLMTimeout, LLMUnavailable))

    def test_kaputtes_json_wirft_llmerror(self):
        with mock.patch(
            "urllib.request.urlopen",
            return_value=_BadJsonResp(b"nicht json"),
        ):
            with self.assertRaises(LLMError):
                self.c.generate(LLMRequest(prompt="x"))

    def test_fehlendes_response_feld(self):
        with mock.patch(
            "urllib.request.urlopen",
            return_value=_FakeResp({"done": True}),
        ):
            with self.assertRaises(LLMError):
                self.c.generate(LLMRequest(prompt="x"))

    def test_antwort_kein_objekt(self):
        with mock.patch(
            "urllib.request.urlopen",
            return_value=_BadJsonResp(b'["liste", "statt", "objekt"]'),
        ):
            with self.assertRaises(LLMError):
                self.c.generate(LLMRequest(prompt="x"))


# ---------------------------------------------------------------------- #
# is_available
# ---------------------------------------------------------------------- #

class OllamaClientAvailabilityTests(unittest.TestCase):
    def test_is_available_true(self):
        c = OllamaClient()
        with mock.patch(
            "urllib.request.urlopen",
            return_value=_FakeResp({}, status=200),
        ):
            self.assertTrue(c.is_available())

    def test_is_available_false_bei_oserror(self):
        c = OllamaClient()
        with mock.patch(
            "urllib.request.urlopen",
            side_effect=OSError("x"),
        ):
            self.assertFalse(c.is_available())

    def test_is_available_false_bei_ungueltigem_timeout(self):
        c = OllamaClient()
        self.assertFalse(c.is_available(timeout=0))
        self.assertFalse(c.is_available(timeout=-1))


if __name__ == "__main__":
    unittest.main()
