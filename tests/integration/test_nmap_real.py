# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Integrationstest fuer tools/nmap_scan.py mit ECHTEM nmap.

Wird uebersprungen, wenn nmap nicht im PATH ist (siehe docs/DEPLOYMENT.md).
Laeuft ausschliesslich gegen 127.0.0.1 (Sandbox-Whitelist).

Kein externes Netz, keine Annahmen ueber offene Ports: wir pruefen nur,
dass der echte subprocess-Pfad durchlaeuft und das Ergebnis-Schema passt.
"""
from __future__ import annotations

import shutil
import socket
import unittest

import pytest

from harness.tool_registry.tool import ToolError
from tools.nmap_scan import nmap_scan_run

pytestmark = pytest.mark.skipif(
    shutil.which("nmap") is None,
    reason="nmap nicht installiert (siehe docs/DEPLOYMENT.md)",
)


def _free_port() -> int:
    """Holt einen freien TCP-Port (nicht gebunden, race-tolerant)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class NmapRealScanTests(unittest.TestCase):
    def test_scan_gegen_localhost(self):
        """
        Echter nmap-Aufruf gegen 127.0.0.1 mit -sT.
        Erwartet: source == "nmap", hosts ist Liste.
        """
        port = _free_port()
        r = nmap_scan_run(
            target="127.0.0.1",
            ports=str(port),
            scan_type="connect",
        )
        self.assertEqual(r["source"], "nmap")
        self.assertEqual(r["target"], "127.0.0.1")
        self.assertEqual(r["scan_type"], "connect")
        self.assertIsInstance(r["hosts"], list)
        self.assertGreaterEqual(len(r["hosts"]), 1)
        host = r["hosts"][0]
        self.assertEqual(host["ip"], "127.0.0.1")
        self.assertIn("state", host)
        self.assertIsInstance(host["ports"], list)

    def test_scan_ohne_ports_gegen_localhost(self):
        """
        Ohne ports-Angabe: nmap nimmt Default-Ports. Wir pruefen nur,
        dass kein ToolError fliegt und das Schema stimmt.
        """
        r = nmap_scan_run(target="127.0.0.1", scan_type="connect")
        self.assertEqual(r["source"], "nmap")
        self.assertIsNone(r["ports"])
        self.assertIsInstance(r["hosts"], list)

    def test_fremdes_ziel_wirft_toolerror(self):
        """
        Ziel ausserhalb der Whitelist muss auch im echten Pfad
        fail-closed sein, ohne nmap aufzurufen.
        """
        with self.assertRaises(ToolError):
            nmap_scan_run(target="8.8.8.8", scan_type="connect")


if __name__ == "__main__":
    unittest.main()
