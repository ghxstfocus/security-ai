# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Unit-Tests fuer tools/nmap_scan.py (echte subprocess-Version).

Deckt die Sandbox-Gates ab:
  - Ziel-Whitelist (Sandbox-Ebene, Defense in Depth)
  - Argument-Whitelist
  - Timeout -> ToolError
  - non-zero exit -> ToolError
  - XML-Parse-Fehler -> ToolError
  - fehlendes nmap-Binary -> ToolError
  - scan_type "syn" / "ping" -> ToolError (Sandbox-Verbot)

Alle subprocess-Aufrufe werden gemockt; kein echtes nmap noetig.
"""
from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from harness.tool_registry.tool import ToolError
from tools.nmap_scan import nmap_scan_run

# ---------------------------------------------------------------------- #
# Test-XML
# ---------------------------------------------------------------------- #

_XML_ONE_HOST = (
    '<?xml version="1.0"?>'
    '<nmaprun>'
    '<host>'
    '<status state="up"/>'
    '<address addr="127.0.0.1" addrtype="ipv4"/>'
    '<hostnames><hostname name="localhost"/></hostnames>'
    '<ports>'
    '<port protocol="tcp" portid="22">'
    '<state state="open"/>'
    '<service name="ssh" product="OpenSSH" version="8.4"/>'
    '</port>'
    '</ports>'
    '</host>'
    '</nmaprun>'
)

_XML_TWO_HOSTS = (
    '<?xml version="1.0"?>'
    '<nmaprun>'
    '<host>'
    '<status state="up"/>'
    '<address addr="192.168.178.1" addrtype="ipv4"/>'
    '<ports>'
    '<port protocol="tcp" portid="80">'
    '<state state="open"/>'
    '<service name="http"/>'
    '</port>'
    '</ports>'
    '</host>'
    '<host>'
    '<status state="down"/>'
    '<address addr="192.168.178.2" addrtype="ipv4"/>'
    '<ports/>'
    '</host>'
    '</nmaprun>'
)


# ---------------------------------------------------------------------- #
# Hilfen
# ---------------------------------------------------------------------- #

def _fake_run_ok(xml=_XML_ONE_HOST, returncode=0, stderr=""):
    def _fake_run(argv, **kwargs):
        return mock.Mock(returncode=returncode, stdout=xml, stderr=stderr)
    return _fake_run


def _patch_ok(xml=_XML_ONE_HOST):
    return mock.patch.multiple(
        "tools.nmap_scan",
        shutil=mock.Mock(which=mock.Mock(return_value="/usr/bin/nmap")),
        subprocess=mock.Mock(run=mock.Mock(side_effect=_fake_run_ok(xml=xml))),
    )


# ---------------------------------------------------------------------- #
# Happy Path / Parsing
# ---------------------------------------------------------------------- #

class NmapHappyPathTests(unittest.TestCase):
    def test_ein_host_vollstaendig(self):
        with _patch_ok():
            r = nmap_scan_run(target="127.0.0.1", ports="22",
                              scan_type="connect")
        self.assertEqual(r["source"], "nmap")
        self.assertEqual(r["target"], "127.0.0.1")
        self.assertEqual(r["ports"], "22")
        self.assertEqual(r["scan_type"], "connect")
        self.assertEqual(len(r["hosts"]), 1)
        h = r["hosts"][0]
        self.assertEqual(h["ip"], "127.0.0.1")
        self.assertEqual(h["hostname"], "localhost")
        self.assertEqual(h["state"], "up")
        self.assertEqual(len(h["ports"]), 1)
        p = h["ports"][0]
        self.assertEqual(p["port"], 22)
        self.assertEqual(p["protocol"], "tcp")
        self.assertEqual(p["state"], "open")
        self.assertEqual(p["service"], "ssh")
        self.assertEqual(p["product"], "OpenSSH")
        self.assertEqual(p["version"], "8.4")

    def test_zwei_hosts_einer_down(self):
        with _patch_ok(xml=_XML_TWO_HOSTS):
            r = nmap_scan_run(target="192.168.178.0/24",
                              scan_type="connect")
        self.assertEqual(len(r["hosts"]), 2)
        self.assertEqual(r["hosts"][0]["ip"], "192.168.178.1")
        self.assertEqual(r["hosts"][0]["state"], "up")
        self.assertEqual(r["hosts"][1]["ip"], "192.168.178.2")
        self.assertEqual(r["hosts"][1]["state"], "down")
        self.assertEqual(r["hosts"][1]["ports"], [])

    def test_argv_enthaelt_whitelist_flags(self):
        captured = {}

        def _fake_run(argv, **kwargs):
            captured["argv"] = argv
            return mock.Mock(returncode=0, stdout=_XML_ONE_HOST, stderr="")

        with mock.patch("tools.nmap_scan.shutil.which",
                        return_value="/usr/bin/nmap"), mock.patch("tools.nmap_scan.subprocess.run",
                        side_effect=_fake_run):
            nmap_scan_run(target="127.0.0.1", ports="22,80",
                          scan_type="connect")
        argv = captured["argv"]
        self.assertEqual(argv[0], "nmap")
        self.assertIn("-sT", argv)
        self.assertIn("-oX", argv)
        self.assertIn("-", argv)
        self.assertIn("-Pn", argv)
        self.assertIn("-n", argv)
        self.assertIn("-p", argv)
        self.assertEqual(argv[argv.index("-p") + 1], "22,80")
        self.assertEqual(argv[-1], "127.0.0.1")


# ---------------------------------------------------------------------- #
# Ziel-Whitelist (Sandbox-Ebene)
# ---------------------------------------------------------------------- #

class NmapTargetWhitelistTests(unittest.TestCase):
    def test_ziel_ausserhalb_whitelist_wirft_toolerror(self):
        with mock.patch("tools.nmap_scan.subprocess.run") as m:
            with self.assertRaises(ToolError):
                nmap_scan_run(target="8.8.8.8", scan_type="connect")
            self.assertFalse(m.called,
                             "subprocess.run darf vor Whitelist-Check "
                             "nicht aufgerufen werden")

    def test_ziel_private_ranges_erlaubt(self):
        for target in ("127.0.0.1", "10.1.2.3", "172.16.5.5",
                       "192.168.178.1", "localhost"):
            with _patch_ok():
                r = nmap_scan_run(target=target, scan_type="connect")
            self.assertEqual(r["source"], "nmap", target)

    def test_ziel_oeffentlich_ipv6_nicht_erlaubt(self):
        with mock.patch("tools.nmap_scan.subprocess.run"), self.assertRaises(ToolError):
            nmap_scan_run(target="2001:4860:4860::8888",
                          scan_type="connect")

    def test_nmap_netz_ueberspannt_whitelist(self):
        # 192.168.0.0/16 ist NICHT subnet_of 192.168.0.0/16-Whitelist-Eintrag
        # in _ALLOWED_NETWORKS? Doch - 192.168.0.0/16 IST in der Whitelist.
        # Deshalb nehmen wir 192.168.0.0/15, das die Whitelist ueberspannt.
        with mock.patch("tools.nmap_scan.subprocess.run") as m:
            with self.assertRaises(ToolError):
                nmap_scan_run(target="192.168.0.0/15", scan_type="connect")
            self.assertFalse(m.called)

    def test_nmap_netz_teilmenge_erlaubt(self):
        captured = {}

        def _fake_run(argv, **kwargs):
            captured["argv"] = argv
            return mock.Mock(returncode=0, stdout=_XML_ONE_HOST, stderr="")

        with mock.patch("tools.nmap_scan.shutil.which",
                        return_value="/usr/bin/nmap"), mock.patch("tools.nmap_scan.subprocess.run",
                        side_effect=_fake_run):
            r = nmap_scan_run(target="192.168.178.0/25",
                              scan_type="connect")
        self.assertEqual(r["source"], "nmap")
        self.assertEqual(captured["argv"][-1], "192.168.178.0/25")


# ---------------------------------------------------------------------- #
# scan_type-Verbote
# ---------------------------------------------------------------------- #

class NmapScanTypeTests(unittest.TestCase):
    def test_syn_wirft_toolerror(self):
        with self.assertRaises(ToolError):
            nmap_scan_run(target="127.0.0.1", scan_type="syn")

    def test_ping_wirft_toolerror(self):
        with self.assertRaises(ToolError):
            nmap_scan_run(target="127.0.0.1", scan_type="ping")

    def test_unbekannt_wirft_toolargumenterror(self):
        from harness.tool_registry.tool import ToolArgumentError
        with self.assertRaises(ToolArgumentError):
            nmap_scan_run(target="127.0.0.1", scan_type="magic")


# ---------------------------------------------------------------------- #
# subprocess-Fehler
# ---------------------------------------------------------------------- #

class NmapSubprocessErrorTests(unittest.TestCase):
    def test_timeout_wirft_toolerror(self):
        def _raise(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="nmap", timeout=30)
        with mock.patch("tools.nmap_scan.shutil.which",
                        return_value="/usr/bin/nmap"), mock.patch("tools.nmap_scan.subprocess.run",
                        side_effect=_raise), self.assertRaises(ToolError):
            nmap_scan_run(target="127.0.0.1", scan_type="connect")

    def test_nonzero_exit_wirft_toolerror(self):
        with mock.patch("tools.nmap_scan.shutil.which",
                        return_value="/usr/bin/nmap"), mock.patch(
            "tools.nmap_scan.subprocess.run",
            side_effect=_fake_run_ok(returncode=1, stderr="boom"),
        ), self.assertRaises(ToolError):
            nmap_scan_run(target="127.0.0.1", scan_type="connect")

    def test_xml_parse_fehler_wirft_toolerror(self):
        with mock.patch("tools.nmap_scan.shutil.which",
                        return_value="/usr/bin/nmap"), mock.patch(
            "tools.nmap_scan.subprocess.run",
            side_effect=_fake_run_ok(xml="nicht xml"),
        ), self.assertRaises(ToolError):
            nmap_scan_run(target="127.0.0.1", scan_type="connect")

    def test_fehlendes_binary_wirft_toolerror(self):
        with mock.patch("tools.nmap_scan.shutil.which",
                        return_value=None), self.assertRaises(ToolError):
            nmap_scan_run(target="127.0.0.1", scan_type="connect")


if __name__ == "__main__":
    unittest.main()
