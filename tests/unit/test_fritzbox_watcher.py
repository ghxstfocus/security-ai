"""Tests fuer tools/fritzbox_watcher.py (A1119).

Fritz!Box-Client gemockt (monkeypatch auf _fetch_hosts
oder FritzHosts), AuditWriter gemockt. Keine echte
Fritz!Box, keine Netzwerkaufrufe.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from core.events.event import EventType
from tools import fritzbox_watcher as fw


def _host(mac: str, ip: str = "10.0.0.1",
          name: str = "kamera", active: bool = True) -> dict:
    return {"mac": mac, "ip": ip, "name": name, "active": active}


class LoadStateTests(unittest.TestCase):
    def test_missing_file(self) -> None:
        with TemporaryDirectory() as d:
            p = Path(d) / "state.json"
            state = fw._load_state(p)
            self.assertEqual(state["version"], fw._STATE_FORMAT_VERSION)
            self.assertEqual(state["hosts"], {})

    def test_existing_file(self) -> None:
        with TemporaryDirectory() as d:
            p = Path(d) / "state.json"
            p.write_text(json.dumps({
                "version": fw._STATE_FORMAT_VERSION,
                "hosts": {"aa:bb": {"ip": "10.0.0.1",
                                    "name": "x", "active": True}},
            }), encoding="utf-8")
            state = fw._load_state(p)
            self.assertIn("aa:bb", state["hosts"])

    def test_corrupt_file(self) -> None:
        with TemporaryDirectory() as d:
            p = Path(d) / "state.json"
            p.write_text("{not json", encoding="utf-8")
            state = fw._load_state(p)
            self.assertEqual(state["hosts"], {})

    def test_unknown_version(self) -> None:
        with TemporaryDirectory() as d:
            p = Path(d) / "state.json"
            p.write_text(json.dumps(
                {"version": 99, "hosts": {"aa:bb": {}}}
            ), encoding="utf-8")
            state = fw._load_state(p)
            self.assertEqual(state["hosts"], {})


class SaveStateTests(unittest.TestCase):
    def test_atomic(self) -> None:
        with TemporaryDirectory() as d:
            p = Path(d) / "state.json"
            fw._save_state({"version": 1, "hosts": {}}, p)
            self.assertTrue(p.exists())
            data = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(data["version"], 1)


class DiffEmitTests(unittest.TestCase):
    def test_empty_to_three(self) -> None:
        state = fw._empty_state()
        hosts = [
            _host("aa:aa:aa:aa:aa:01"),
            _host("aa:aa:aa:aa:aa:02"),
            _host("aa:aa:aa:aa:aa:03"),
        ]
        events = fw._diff_and_emit(state, hosts)
        self.assertEqual(len(events), 3)
        for e in events:
            self.assertEqual(
                e.event_type, EventType.DEVICE_PRESENCE.value
            )

    def test_unchanged(self) -> None:
        state = {
            "version": fw._STATE_FORMAT_VERSION,
            "hosts": {"aa:01": {"ip": "10.0.0.1",
                                "name": "x", "active": True}},
        }
        hosts = [_host("aa:01", active=True)]
        events = fw._diff_and_emit(state, hosts)
        self.assertEqual(events, [])

    def test_offline(self) -> None:
        state = {
            "version": fw._STATE_FORMAT_VERSION,
            "hosts": {"aa:01": {"ip": "10.0.0.1",
                                "name": "x", "active": True}},
        }
        hosts = [_host("aa:01", active=False)]
        events = fw._diff_and_emit(state, hosts)
        self.assertEqual(len(events), 1)
        self.assertEqual(
            events[0].event_type, EventType.DEVICE_OFFLINE.value
        )

    def test_new_inactive(self) -> None:
        state = fw._empty_state()
        hosts = [_host("aa:01", active=False)]
        events = fw._diff_and_emit(state, hosts)
        self.assertEqual(events, [])

    def test_was_inactive_now_active(self) -> None:
        state = {
            "version": fw._STATE_FORMAT_VERSION,
            "hosts": {"aa:01": {"ip": "10.0.0.1",
                                "name": "x", "active": False}},
        }
        hosts = [_host("aa:01", active=True)]
        events = fw._diff_and_emit(state, hosts)
        self.assertEqual(len(events), 1)
        self.assertEqual(
            events[0].event_type, EventType.DEVICE_PRESENCE.value
        )

    def test_data_fields(self) -> None:
        state = fw._empty_state()
        hosts = [_host("aa:01", ip="192.168.189.5",
                       name="kamera", active=True)]
        events = fw._diff_and_emit(state, hosts)
        d = events[0].data
        self.assertEqual(d["identifier"], "aa:01")
        self.assertEqual(d["mac"], "aa:01")
        self.assertEqual(d["ip"], "192.168.189.5")
        self.assertEqual(d["entity_name"], "kamera")
        self.assertEqual(d["network_type"], "Gastnetz")
        self.assertNotIn("known", d)


class RunTests(unittest.TestCase):
    def _patch_ok(self):
        return (
            mock.patch.object(
                fw, "get_fritz_credentials",
                return_value=("admin", "pw"),
            ),
            mock.patch.object(fw, "get_fritz_host",
                              return_value="fritz.box"),
            mock.patch.object(fw, "resolve_network_type",
                              return_value="Hauptnetz"),
        )

    def test_credentials_missing(self) -> None:
        from core.config import ConfigError
        with mock.patch.object(
            fw, "get_fritz_credentials",
            side_effect=ConfigError("fehlt"),
        ):
            self.assertEqual(fw.run(), 2)

    def test_fritzbox_unreachable(self) -> None:
        p1, p2, p3 = self._patch_ok()
        with p1, p2, p3, mock.patch.object(
            fw, "_fetch_hosts",
            side_effect=OSError("kein netz"),
        ):
            self.assertEqual(fw.run(), 1)

    def test_write_failure(self) -> None:
        p1, p2, p3 = self._patch_ok()
        with p1, p2, p3, mock.patch.object(
            fw, "_fetch_hosts",
            return_value=[_host("aa:01", active=True)],
        ), mock.patch.object(
            fw, "_write_events",
            side_effect=OSError("kein platz"),
        ), mock.patch.object(
            fw, "_save_state",
        ):
            self.assertEqual(fw.run(), 3)

    def test_no_events_no_audit(self) -> None:
        p1, p2, p3 = self._patch_ok()
        with p1, p2, p3, mock.patch.object(
            fw, "_fetch_hosts", return_value=[],
        ), mock.patch.object(
            fw, "_load_state", return_value=fw._empty_state(),
        ), mock.patch.object(
            fw, "_write_events", return_value=0,
        ), mock.patch.object(
            fw, "_save_state",
        ), mock.patch.object(
            fw, "AuditWriter",
        ) as mock_audit:
            rc = fw.run()
            self.assertEqual(rc, 0)
            mock_audit.assert_not_called()

    def test_events_audit_called(self) -> None:
        p1, p2, p3 = self._patch_ok()
        with p1, p2, p3, mock.patch.object(
            fw, "_fetch_hosts",
            return_value=[_host("aa:01", active=True)],
        ), mock.patch.object(
            fw, "_load_state", return_value=fw._empty_state(),
        ), mock.patch.object(
            fw, "_write_events", return_value=1,
        ), mock.patch.object(
            fw, "_save_state",
        ), mock.patch.object(
            fw, "AuditWriter",
        ) as mock_audit:
            rc = fw.run()
            self.assertEqual(rc, 0)
            self.assertTrue(mock_audit.called)
            self.assertTrue(mock_audit.return_value.log.called)


class WriteEventsModeTests(unittest.TestCase):
    def test_new_file_mode_640(self) -> None:
        import os

        from core.events.event import (
            EventType,
            Severity,
            new_event,
        )
        with TemporaryDirectory() as d:
            p = Path(d) / "events-test.jsonl"
            e = new_event(
                source="fritzbox",
                event_type=EventType.DEVICE_PRESENCE.value,
                severity=Severity.INFO,
                data={"identifier": "aa:bb:cc:dd:ee:01"},
            )
            n = fw._write_events([e], p)
            self.assertEqual(n, 1)
            mode = os.stat(p).st_mode & 0o777
            self.assertEqual(
                mode, 0o640,
                f"erwartet 0o640, ist {oct(mode)}",
            )

    def test_no_events_no_file(self) -> None:
        with TemporaryDirectory() as d:
            p = Path(d) / "events-empty.jsonl"
            n = fw._write_events([], p)
            self.assertEqual(n, 0)
            self.assertFalse(p.exists())


if __name__ == "__main__":
    unittest.main()
