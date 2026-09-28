"""Tests fuer alle Tools: Definition, Validierung, Verhalten."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.inventory.repository import DeviceRepository, apply_migrations, connect
from core.inventory.whitelist import WhitelistRepository
from harness.permissions.levels import Level
from harness.policy_engine.engine import PolicyEngine
from harness.policy_engine.policy import Decision, PolicyContext
from harness.tool_registry.registry import ToolRegistry
from harness.tool_registry.tool import Tool, ToolArgumentError, ToolError
from tools.get_devices import GET_DEVICES_TOOL, get_devices_run
from tools.nmap_scan import NMAP_SCAN_TOOL, nmap_scan_run
from tools.read_logs import READ_LOGS_TOOL, read_logs_run
from tools.telegram_alert import TELEGRAM_ALERT_TOOL, telegram_alert_run
from tools.whitelist_check import WHITELIST_CHECK_TOOL, whitelist_check_run

ALL_TOOLS = [
    NMAP_SCAN_TOOL,
    READ_LOGS_TOOL,
    GET_DEVICES_TOOL,
    WHITELIST_CHECK_TOOL,
    TELEGRAM_ALERT_TOOL,
]


# ---------------------------------------------------------------------- #
# Definitionen
# ---------------------------------------------------------------------- #

class ToolDefinitionTests(unittest.TestCase):
    def test_alle_sind_tool(self):
        for t in ALL_TOOLS:
            self.assertIsInstance(t, Tool, t.name)

    def test_erwartete_level(self):
        self.assertIs(NMAP_SCAN_TOOL.level, Level.SECURITY_ACTION)
        self.assertIs(READ_LOGS_TOOL.level, Level.READ)
        self.assertIs(GET_DEVICES_TOOL.level, Level.READ)
        self.assertIs(WHITELIST_CHECK_TOOL.level, Level.READ)
        self.assertIs(TELEGRAM_ALERT_TOOL.level, Level.SECURITY_ACTION)

    def test_sandbox_profile_gesetzt(self):
        for t in ALL_TOOLS:
            self.assertIsNotNone(t.sandbox_profile, t.name)
            self.assertNotEqual(t.sandbox_profile, "", t.name)

    def test_returns_dict(self):
        for t in ALL_TOOLS:
            self.assertEqual(t.returns, "dict", t.name)

    def test_allowed_args_nicht_leer(self):
        for t in ALL_TOOLS:
            self.assertTrue(t.allowed_args, t.name)

    def test_kein_underscore_in_allowed_args(self):
        for t in ALL_TOOLS:
            for a in t.allowed_args:
                self.assertFalse(a.startswith("_"),
                                 f"{t.name}: {a} darf nicht in allowed_args")

    def test_registry_nimmt_alle(self):
        reg = ToolRegistry()
        reg.register_many(ALL_TOOLS)
        self.assertEqual(len(reg), len(ALL_TOOLS))
        for t in ALL_TOOLS:
            self.assertTrue(reg.has(t.name))

    def test_namen_eindeutig(self):
        names = [t.name for t in ALL_TOOLS]
        self.assertEqual(len(names), len(set(names)))


# ---------------------------------------------------------------------- #
# nmap_scan
# ---------------------------------------------------------------------- #

class NmapScanTests(unittest.TestCase):
    _FAKE_XML = (
        '<?xml version="1.0"?>'
        '<nmaprun>'
        '<host>'
        '<status state="up"/>'
        '<address addr="192.168.178.1" addrtype="ipv4"/>'
        '<hostnames><hostname name="router.local"/></hostnames>'
        '<ports>'
        '<port protocol="tcp" portid="22">'
        '<state state="open"/>'
        '<service name="ssh" product="OpenSSH" version="8.4"/>'
        '</port>'
        '<port protocol="tcp" portid="80">'
        '<state state="open"/>'
        '<service name="http" product="nginx" version="1.18"/>'
        '</port>'
        '</ports>'
        '</host>'
        '</nmaprun>'
    )

    def _fake_run_ok(self, xml=None, returncode=0, stderr=""):
        def _fake_run(argv, **kwargs):
            return mock.Mock(
                returncode=returncode,
                stdout=(xml if xml is not None else self._FAKE_XML),
                stderr=stderr,
            )
        return _fake_run

    def _patch_ok(self, xml=None, returncode=0, stderr=""):
        return mock.patch.multiple(
            "tools.nmap_scan",
            shutil=mock.Mock(which=mock.Mock(return_value="/usr/bin/nmap")),
            subprocess=mock.Mock(
                run=mock.Mock(side_effect=self._fake_run_ok(
                    xml=xml, returncode=returncode, stderr=stderr
                ))
            ),
        )

    def test_nmap_mock_subprocess_ok(self):
        with self._patch_ok():
            r = nmap_scan_run(target="192.168.178.1", ports="22,80",
                              scan_type="connect")
        self.assertEqual(r["source"], "nmap")
        self.assertEqual(r["target"], "192.168.178.1")
        self.assertEqual(r["ports"], "22,80")
        self.assertEqual(r["scan_type"], "connect")
        self.assertEqual(len(r["hosts"]), 1)
        h = r["hosts"][0]
        self.assertEqual(h["ip"], "192.168.178.1")
        self.assertEqual(h["hostname"], "router.local")
        self.assertEqual(h["state"], "up")
        self.assertEqual(len(h["ports"]), 2)
        self.assertEqual(h["ports"][0]["port"], 22)
        self.assertEqual(h["ports"][0]["service"], "ssh")
        self.assertEqual(h["ports"][0]["state"], "open")

    def test_defaults_argv_enthaelt_sT_oX(self):
        captured = {}

        def _fake_run(argv, **kwargs):
            captured["argv"] = argv
            return mock.Mock(returncode=0, stdout=self._FAKE_XML, stderr="")

        with mock.patch("tools.nmap_scan.shutil.which",
                        return_value="/usr/bin/nmap"), mock.patch("tools.nmap_scan.subprocess.run",
                        side_effect=_fake_run):
            r = nmap_scan_run(target="192.168.178.1")
        self.assertIsNone(r["ports"])
        self.assertEqual(r["scan_type"], "connect")
        argv = captured["argv"]
        self.assertEqual(argv[0], "nmap")
        self.assertIn("-sT", argv)
        self.assertIn("-oX", argv)
        self.assertIn("-", argv)
        self.assertEqual(argv[-1], "192.168.178.1")

    def test_ports_als_liste_wird_komma_string(self):
        captured = {}

        def _fake_run(argv, **kwargs):
            captured["argv"] = argv
            return mock.Mock(returncode=0, stdout=self._FAKE_XML, stderr="")

        with mock.patch("tools.nmap_scan.shutil.which",
                        return_value="/usr/bin/nmap"), mock.patch("tools.nmap_scan.subprocess.run",
                        side_effect=_fake_run):
            r = nmap_scan_run(target="192.168.178.1", ports=[22, 80])
        self.assertEqual(r["ports"], "22,80")
        argv = captured["argv"]
        self.assertIn("-p", argv)
        self.assertEqual(argv[argv.index("-p") + 1], "22,80")

    def test_validierung(self):
        for bad in [
            dict(target=""),
            dict(target=None),
            dict(target=123),
            dict(target="x" * 300),
            dict(target="x", ports="22; rm -rf /"),
            dict(target="x", ports=[22, "a"]),
            dict(target="x", scan_type="unbekannt"),
        ]:
            with self.assertRaises(ToolArgumentError, msg=bad):
                nmap_scan_run(**bad)

    def test_syn_scan_wirft_toolerror(self):
        with self.assertRaises(ToolError):
            nmap_scan_run(target="192.168.178.1", scan_type="syn")

    def test_ping_scan_wirft_toolerror(self):
        with self.assertRaises(ToolError):
            nmap_scan_run(target="192.168.178.1", scan_type="ping")

    def test_validate_args(self):
        NMAP_SCAN_TOOL.validate_args({"target": "x"})
        with self.assertRaises(ToolArgumentError):
            NMAP_SCAN_TOOL.validate_args({"target": "x", "unbekannt": 1})


# ---------------------------------------------------------------------- #
# read_logs
# ---------------------------------------------------------------------- #

class ReadLogsTests(unittest.TestCase):
    def test_mock_ergebnis(self):
        r = read_logs_run(path="/var/log/syslog")
        self.assertEqual(r["source"], "mock")
        self.assertEqual(r["path"], "/var/log/syslog")
        self.assertEqual(r["max_lines"], 200)
        self.assertEqual(r["lines"], [])

    def test_max_lines(self):
        r = read_logs_run(path="/var/log/syslog", max_lines=50)
        self.assertEqual(r["max_lines"], 50)

    def test_pfad_abgelehnt(self):
        # Shell-Zeichen mitten im Pfad, Path-Traversal, falscher Prefix
        for bad in [
            "",
            "/etc/passwd",
            "/var/log/../../etc/passwd",
            "/var/log/syslog; rm -rf /",
            "/var/log/syslog | cat",
            "/var/log/syslog\nrm -rf /",
        ]:
            with self.assertRaises(ToolArgumentError, msg=bad):
                read_logs_run(path=bad)

    def test_pfad_erlaubt_mit_whitespace_rand(self):
        # Whitespace am Rand wird getrimmt, kein Fehler
        for ok in [
            "/var/log/syslog",
            "/var/log/syslog\n",
            "  /var/log/syslog  ",
            "/var/log/syslog ", 
        ]:
            r = read_logs_run(path=ok)
            self.assertEqual(r["path"], "/var/log/syslog", ok)

    def test_max_lines_validierung(self):
        for bad in [0, -1, 1001, "viele", None, True]:
            with self.assertRaises(ToolArgumentError, msg=bad):
                read_logs_run(path="/var/log/syslog", max_lines=bad)

    def test_validate_args(self):
        READ_LOGS_TOOL.validate_args({"path": "/var/log/syslog"})
        with self.assertRaises(ToolArgumentError):
            READ_LOGS_TOOL.validate_args({"path": "/var/log/syslog", "x": 1})


# ---------------------------------------------------------------------- #
# get_devices
# ---------------------------------------------------------------------- #

class GetDevicesTests(unittest.TestCase):
    def test_mock_ohne_db(self):
        r = get_devices_run(mock=True)
        self.assertEqual(r["source"], "mock")
        self.assertEqual(r["count"], 0)

    def test_mock_mit_identifier(self):
        r = get_devices_run(identifier="192.168.178.1", mock=True)
        self.assertEqual(r["source"], "mock")
        self.assertEqual(r["count"], 1)
        self.assertEqual(r["devices"][0]["identifier"], "192.168.178.1")

    def test_fehlende_db_toolerror(self):
        with self.assertRaises(ToolError):
            get_devices_run(db_path="/tmp/gibt-es-nicht-xyz.db")

    def test_echte_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "inv.db"
            conn = connect(db)
            apply_migrations(conn)
            repo = DeviceRepository(conn)
            repo.upsert_seen("192.168.178.87", entity_name="Ghxst-Server",
                             network_type="Hauptnetz")
            repo.upsert_seen("192.168.178.10", entity_name="Laptop",
                             network_type="Hauptnetz")
            conn.close()

            r = get_devices_run(db_path=str(db))
            self.assertEqual(r["source"], "db")
            self.assertEqual(r["count"], 2)
            names = {d["identifier"] for d in r["devices"]}
            self.assertEqual(names, {"192.168.178.87", "192.168.178.10"})

            r = get_devices_run(identifier="192.168.178.87", db_path=str(db))
            self.assertEqual(r["count"], 1)
            self.assertEqual(r["devices"][0]["entity_name"], "Ghxst-Server")

            r = get_devices_run(identifier="10.0.0.99", db_path=str(db))
            self.assertEqual(r["count"], 0)

    def test_argument_validierung(self):
        for bad in [
            dict(identifier=123),
            dict(identifier=""),
            dict(mock="ja"),
            dict(db_path=123),
        ]:
            with self.assertRaises(ToolArgumentError, msg=bad):
                get_devices_run(**bad)


# ---------------------------------------------------------------------- #
# whitelist_check
# ---------------------------------------------------------------------- #

class WhitelistCheckTests(unittest.TestCase):
    def test_mock_liste_ohne_is_whitelisted(self):
        r = whitelist_check_run(mock=True)
        self.assertEqual(r["source"], "mock")
        self.assertIn("identifiers", r)
        self.assertNotIn("is_whitelisted", r)
        self.assertNotIn("identifier", r)

    def test_mock_identifier_ohne_identifiers(self):
        r = whitelist_check_run(identifier="10.0.0.1", mock=True)
        self.assertEqual(r["source"], "mock")
        self.assertIn("identifier", r)
        self.assertIn("is_whitelisted", r)
        self.assertNotIn("identifiers", r)

    def test_fehlende_db_toolerror(self):
        with self.assertRaises(ToolError):
            whitelist_check_run(db_path="/tmp/gibt-es-nicht-xyz.db")

    def test_echte_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "inv.db"
            conn = connect(db)
            apply_migrations(conn)
            wl = WhitelistRepository(conn)
            wl.add("192.168.178.10", "Laptop", added_by="admin")
            wl.add("192.168.178.11", "Drucker", added_by="admin")
            conn.close()

            r = whitelist_check_run(db_path=str(db))
            self.assertEqual(r["source"], "db")
            self.assertEqual(r["count"], 2)
            self.assertNotIn("is_whitelisted", r)

            r = whitelist_check_run(identifier="192.168.178.10",
                                    db_path=str(db))
            self.assertTrue(r["is_whitelisted"])
            self.assertNotIn("identifiers", r)

            r = whitelist_check_run(identifier="10.0.0.99", db_path=str(db))
            self.assertFalse(r["is_whitelisted"])


# ---------------------------------------------------------------------- #
# telegram_alert
# ---------------------------------------------------------------------- #

class TelegramAlertTests(unittest.TestCase):
    def setUp(self):
        self.old_token = os.environ.pop("TELEGRAM_BOT_TOKEN", None)
        self.old_chat = os.environ.pop("TELEGRAM_CHAT_ID", None)

    def tearDown(self):
        if self.old_token is not None:
            os.environ["TELEGRAM_BOT_TOKEN"] = self.old_token
        else:
            os.environ.pop("TELEGRAM_BOT_TOKEN", None)
        if self.old_chat is not None:
            os.environ["TELEGRAM_CHAT_ID"] = self.old_chat
        else:
            os.environ.pop("TELEGRAM_CHAT_ID", None)

    def test_fehlende_env_toolerror(self):
        with self.assertRaises(ToolError):
            telegram_alert_run(title="x", message="y")

    def test_validierung_vor_env_check(self):
        for bad in [
            dict(title="", message="y"),
            dict(title="x", message=""),
            dict(title="x", message="y", severity="unbekannt"),
            dict(title=123, message="y"),
            dict(title="x", message=123),
        ]:
            with self.assertRaises(ToolArgumentError, msg=bad):
                telegram_alert_run(**bad)

    def test_verbindungsfehler_toolerror(self):
        os.environ["TELEGRAM_BOT_TOKEN"] = "fake"
        os.environ["TELEGRAM_CHAT_ID"] = "123"
        with self.assertRaises(ToolError):
            telegram_alert_run(
                title="x", message="y",
                _base_url="http://127.0.0.1:1",
            )

    def test_base_url_nicht_in_allowed_args(self):
        self.assertNotIn("_base_url", TELEGRAM_ALERT_TOOL.allowed_args)
        with self.assertRaises(ToolArgumentError):
            TELEGRAM_ALERT_TOOL.validate_args(
                {"title": "a", "message": "b", "_base_url": "x"}
            )


# ---------------------------------------------------------------------- #
# Zusammenspiel mit Policy Engine
# ---------------------------------------------------------------------- #

class PolicyIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.eng = PolicyEngine("policies/tools.yaml")
        self.ctx = PolicyContext(
            network_id="homelab-default",
            authorized_networks=frozenset({"192.168.178.0/24"}),
            config={"read_only_paths": ["/var/log"]},
        )

    def test_alle_tools_haben_policy(self):
        for t in ALL_TOOLS:
            self.assertTrue(
                self.eng.has_tool(t.name),
                f"Tool {t.name} hat keine Policy in policies/tools.yaml",
            )

    def test_nmap_autorisiert_allowed(self):
        d = self.eng.evaluate(
            "nmap_scan", {"target": "192.168.178.0/24"}, self.ctx
        )
        self.assertIs(d.decision, Decision.ALLOWED)

    def test_nmap_fremd_approval(self):
        d = self.eng.evaluate("nmap_scan", {"target": "10.0.0.1"}, self.ctx)
        self.assertIs(d.decision, Decision.APPROVAL_REQUIRED)

    def test_read_logs_ok(self):
        d = self.eng.evaluate(
            "read_logs", {"path": "/var/log/syslog"}, self.ctx
        )
        self.assertIs(d.decision, Decision.ALLOWED)

    def test_read_logs_shell_forbidden(self):
        d = self.eng.evaluate(
            "read_logs", {"path": "/var/log/syslog; rm -rf /"}, self.ctx
        )
        self.assertIs(d.decision, Decision.FORBIDDEN)

    def test_unbekanntes_tool_forbidden(self):
        d = self.eng.evaluate("gibt_es_nicht", {}, self.ctx)
        self.assertIs(d.decision, Decision.FORBIDDEN)


if __name__ == "__main__":
    unittest.main()
