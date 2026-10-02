"""Tests fuer tools/notify_ntfy.py (Punkt 77)."""
from __future__ import annotations

import os
import unittest
from unittest import mock

from harness.tool_registry.tool import ToolError
from tools.notify_ntfy import notify_ntfy_run


class _EnvReset(unittest.TestCase):
    """Setzt NTFY_* zurueck nach jedem Test."""

    def setUp(self):
        self._alt = {
            k: os.environ.get(k)
            for k in ("NTFY_URL", "NTFY_TOPIC", "NTFY_TOKEN")
        }

    def tearDown(self):
        for k, v in self._alt.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _set(self, url="http://ntfy.test:2586", topic="topic",
             token="tkn"):
        if url is None:
            os.environ.pop("NTFY_URL", None)
        else:
            os.environ["NTFY_URL"] = url
        if topic is None:
            os.environ.pop("NTFY_TOPIC", None)
        else:
            os.environ["NTFY_TOPIC"] = topic
        if token is None:
            os.environ.pop("NTFY_TOKEN", None)
        else:
            os.environ["NTFY_TOKEN"] = token


class NotifyNtfyTests(_EnvReset):

    def test_notify_ntfy_config_missing(self):
        self._set(token=None)
        with self.assertRaises(ToolError) as ctx:
            notify_ntfy_run("Test", "Hallo", "INFO")
        self.assertIn("NTFY_TOKEN", str(ctx.exception))

    def test_notify_ntfy_url_missing(self):
        self._set(url=None)
        with self.assertRaises(ToolError) as ctx:
            notify_ntfy_run("Test", "Hallo", "INFO")
        self.assertIn("NTFY_URL", str(ctx.exception))

    @mock.patch("tools.notify_ntfy.requests.post")
    def test_notify_ntfy_ok(self, mock_post):
        self._set()
        m = mock.MagicMock()
        m.status_code = 200
        m.text = ""
        mock_post.return_value = m
        out = notify_ntfy_run("Test", "Hallo", "WARNING")
        self.assertTrue(out["ok"])
        self.assertEqual(out["source"], "ntfy")
        # Prio-Mapping WARNING -> high.
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["headers"]["Priority"], "high")
        self.assertEqual(kwargs["headers"]["Tags"], "warning")

    @mock.patch("tools.notify_ntfy.requests.post")
    def test_notify_ntfy_fail(self, mock_post):
        self._set()
        m = mock.MagicMock()
        m.status_code = 500
        m.text = "server error"
        mock_post.return_value = m
        with self.assertRaises(ToolError) as ctx:
            notify_ntfy_run("Test", "Hallo", "INFO")
        self.assertIn("HTTP 500", str(ctx.exception))

    def test_severity_priority_mapping(self):
        from tools.notify_ntfy import (
            _SEVERITY_TO_PRIORITY,
            _SEVERITY_TO_TAG,
        )
        self.assertEqual(_SEVERITY_TO_PRIORITY["INFO"], "low")
        self.assertEqual(_SEVERITY_TO_PRIORITY["WARNING"], "high")
        self.assertEqual(_SEVERITY_TO_PRIORITY["CRITICAL"], "urgent")
        self.assertEqual(
            _SEVERITY_TO_TAG["CRITICAL"], "rotating_light",
        )


if __name__ == "__main__":
    unittest.main()
