# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer tools/ping.py (Bug E, Auflage 2013)."""
from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from tools.ping import PingError, ping_run


def _proc(returncode: int, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(
        args=["ping"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


class PingIpv4Tests(unittest.TestCase):

    def test_ping_uses_ipv4_flag(self) -> None:
        captured = []
        def fake_run(argv, **kwargs):
            captured.append(argv)
            return _proc(0, "PING ok\n1 packets transmitted\n")
        with patch(
            "tools.ping.subprocess.run",
            side_effect=fake_run,
        ):
            ping_run("192.168.178.1", count=1)
        self.assertEqual(len(captured), 1)
        self.assertIn("-4", captured[0])

    def test_ping_empty_stdout_raises(self) -> None:
        with patch(
            "tools.ping.subprocess.run",
            return_value=_proc(
                2, "", "ping: socket: family not supported"
            ),
        ), self.assertRaises(PingError):
            ping_run("192.168.178.1", count=1)

    def test_ping_success(self) -> None:
        stdout = (
            "PING 192.168.178.1 (192.168.178.1) 56 bytes\n"
            "1 packets transmitted, 1 received, 0% loss\n"
        )
        with patch(
            "tools.ping.subprocess.run",
            return_value=_proc(0, stdout),
        ):
            result = ping_run("192.168.178.1", count=1)
        self.assertEqual(result["returncode"], 0)
        self.assertIn("received", result["stdout"])
        self.assertEqual(result["source"], "ping")


if __name__ == "__main__":
    unittest.main()
