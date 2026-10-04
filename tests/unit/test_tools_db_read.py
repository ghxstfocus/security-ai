# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer db_read-Tools (Punkt 58 Runde 1, Schritt 5)."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from harness.tool_registry.tool import ToolError
from tools.audit_tail import audit_tail_run
from tools.event_tail import event_tail_run


class AuditTailTests(unittest.TestCase):
    def test_audit_tail_ok(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            from datetime import UTC, datetime
            heute = datetime.now(UTC).strftime("%Y-%m-%d")
            fp = tdp / f"{heute}.jsonl"
            zeilen = [
                json.dumps({"audit_id": f"AUD-{i}", "tool": "t"})
                for i in range(5)
            ]
            fp.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
            with mock.patch("tools.audit_tail._AUDIT_DIR", tdp):
                result = audit_tail_run(limit=3)
            self.assertEqual(result["count"], 3)
            self.assertEqual(result["source"], "audit_tail")
            self.assertEqual(result["entries"][0]["audit_id"], "AUD-2")

    def test_audit_tail_invalid_limit(self) -> None:
        with self.assertRaises(ToolError):
            audit_tail_run(limit=0)
        with self.assertRaises(ToolError):
            audit_tail_run(limit=999)

    def test_audit_tail_skip_malformed_line(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            from datetime import UTC, datetime
            heute = datetime.now(UTC).strftime("%Y-%m-%d")
            fp = tdp / f"{heute}.jsonl"
            fp.write_text(
                json.dumps({"audit_id": "A1"}) + "\n"
                + "kein json\n"
                + json.dumps({"audit_id": "A2"}) + "\n",
                encoding="utf-8",
            )
            with mock.patch("tools.audit_tail._AUDIT_DIR", tdp):
                result = audit_tail_run(limit=10)
            self.assertEqual(result["count"], 2)


class EventTailTests(unittest.TestCase):
    def test_event_tail_ok(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            from datetime import UTC, datetime
            heute = datetime.now(UTC).strftime("%Y-%m-%d")
            fp = tdp / f"events-{heute}.jsonl"
            zeilen = [
                json.dumps({"event_id": f"EVT-{i}", "event_type": "t"})
                for i in range(5)
            ]
            fp.write_text(chr(10).join(zeilen) + chr(10), encoding="utf-8")
            with mock.patch("tools.event_tail._EVENTS_DIR", tdp):
                result = event_tail_run(limit=3)
            self.assertEqual(result["count"], 3)
            self.assertEqual(result["source"], "event_tail")
            self.assertEqual(result["events"][0]["event_id"], "EVT-2")

    def test_event_tail_invalid_limit(self) -> None:
        with self.assertRaises(ToolError):
            event_tail_run(limit=0)
        with self.assertRaises(ToolError):
            event_tail_run(limit=999)

    def test_event_tail_skip_malformed_line(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            from datetime import UTC, datetime
            heute = datetime.now(UTC).strftime("%Y-%m-%d")
            fp = tdp / f"events-{heute}.jsonl"
            fp.write_text(
                json.dumps({"event_id": "E1"}) + chr(10)
                + "kein json" + chr(10)
                + json.dumps({"event_id": "E2"}) + chr(10),
                encoding="utf-8",
            )
            with mock.patch("tools.event_tail._EVENTS_DIR", tdp):
                result = event_tail_run(limit=10)
            self.assertEqual(result["count"], 2)


if __name__ == "__main__":
    unittest.main()
