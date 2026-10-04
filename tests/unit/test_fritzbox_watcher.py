# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

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
from core.sentinels import FALLBACK_SENTINEL
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
        """Unveraenderter Zustand (name, ip, active gleich) -> kein Event.

        Punkt 68: seit Re-Presence prueft _diff_and_emit auch
        name und ip. Der Test muss den old_state daher mit
        denselben Werten bauen, die _host liefert.
        """
        state = {
            "version": fw._STATE_FORMAT_VERSION,
            "hosts": {"aa:01": {"ip": "10.0.0.1",
                                "name": "kamera", "active": True}},
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


class FetchHostsIpNormalizationTests(unittest.TestCase):
    """_fetch_hosts: leere IP wird zu None (Punkt 67b, Auflage 1756)."""

    def _run_fetch(self, rohdaten: list) -> list:
        class FakeConn:
            def __init__(self, **kw: object) -> None:
                pass

        class FakeHosts:
            def __init__(self, fc: object) -> None:
                pass

            def get_hosts_info(self) -> list:
                return rohdaten

        with mock.patch.object(fw, "FritzConnection", FakeConn), \
                mock.patch.object(fw, "FritzHosts", FakeHosts):
            return fw._fetch_hosts("fritz.box", "user", "pw")

    def test_empty_ip_becomes_none(self) -> None:
        hosts = self._run_fetch([
            {"mac": "aa:01", "ip": "", "name": "ohne-ip", "status": True},
        ])
        self.assertEqual(len(hosts), 1)
        self.assertIsNone(hosts[0]["ip"])

    def test_valid_ip_stays(self) -> None:
        hosts = self._run_fetch([
            {"mac": "aa:02", "ip": "192.168.178.5", "name": "mit-ip",
             "status": True},
        ])
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["ip"], "192.168.178.5")

    def test_missing_ip_key_becomes_none(self) -> None:
        hosts = self._run_fetch([
            {"mac": "aa:03", "name": "kein-ip-key", "status": True},
        ])
        self.assertEqual(len(hosts), 1)
        self.assertIsNone(hosts[0]["ip"])


class RePresenceTests(unittest.TestCase):
    """_diff_and_emit: Re-Presence bei name/ip-Diff (Punkt 68)."""

    def _state_with(self, mac: str, name: str, ip: str,
                    active: bool = True) -> dict:
        return {
            "version": fw._STATE_FORMAT_VERSION,
            "hosts": {mac: {"name": name, "ip": ip, "active": active}},
        }

    def _hosts(self, mac: str, name: str, ip: str,
               active: bool = True) -> list:
        return [_host(mac, ip=ip, name=name, active=active)]

    def test_name_changed_emits_event(self) -> None:
        old = self._state_with("aa:10", "kamera", "10.0.0.1")
        hosts = self._hosts("aa:10", "kamera-neu", "10.0.0.1")
        events = fw._diff_and_emit(old, hosts)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type,
                         EventType.DEVICE_PRESENCE.value)

    def test_ip_changed_emits_event(self) -> None:
        old = self._state_with("aa:11", "kamera", "10.0.0.1")
        hosts = self._hosts("aa:11", "kamera", "10.0.0.2")
        events = fw._diff_and_emit(old, hosts)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type,
                         EventType.DEVICE_PRESENCE.value)

    def test_no_change_no_event(self) -> None:
        old = self._state_with("aa:12", "kamera", "10.0.0.1")
        hosts = self._hosts("aa:12", "kamera", "10.0.0.1")
        events = fw._diff_and_emit(old, hosts)
        self.assertEqual(len(events), 0)

    def test_old_without_name_field_emits_event(self) -> None:
        old = {
            "version": fw._STATE_FORMAT_VERSION,
            "hosts": {"aa:13": {"ip": "10.0.0.1", "active": True}},
        }
        hosts = self._hosts("aa:13", "kamera", "10.0.0.1")
        events = fw._diff_and_emit(old, hosts)
        self.assertEqual(len(events), 1)

    def test_sentinel_vs_sentinel_no_event(self) -> None:
        old = self._state_with("aa:14", FALLBACK_SENTINEL, "10.0.0.1")
        hosts = self._hosts("aa:14", FALLBACK_SENTINEL, "10.0.0.1")
        events = fw._diff_and_emit(old, hosts)
        self.assertEqual(len(events), 0)

    def test_sentinel_wird_none_im_event(self) -> None:
        from core.sentinels import FALLBACK_SENTINEL
        from tools.fritzbox_watcher import _diff_and_emit
        old = {"hosts": {}}
        new = [{"ip": "10.0.0.1", "mac": "aa:01", "name": FALLBACK_SENTINEL, "active": True}]
        events = _diff_and_emit(old, new)
        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0].data["entity_name"])
