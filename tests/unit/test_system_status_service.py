# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests SystemStatusService (Punkt 66, Kategorie 3)."""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from core.access.checker import AccessDeniedError
from core.services.system_status_service import (
    UNIT_WHITELIST,
    SystemStatusOperationError,
    SystemStatusService,
)


def _checker_allow() -> MagicMock:
    c = MagicMock()
    c.require_permission = MagicMock(return_value=None)
    return c


def _checker_deny() -> MagicMock:
    c = MagicMock()
    c.require_permission = MagicMock(
        side_effect=AccessDeniedError("denied"),
    )
    return c


class SystemStatusServiceTests(unittest.TestCase):

    def test_snapshot_rbac_denied(self) -> None:
        svc = SystemStatusService(checker=_checker_deny())
        with self.assertRaises(AccessDeniedError):
            svc.get_snapshot("viewer1")

    def test_snapshot_returns_all_fields(self) -> None:
        svc = SystemStatusService(checker=_checker_allow())
        snap = svc.get_snapshot("admin1")
        for key in (
            "cpu_percent", "cpu_count",
            "ram_percent", "ram_used_gb", "ram_total_gb",
            "disk_root_percent",
            "disk_root_used_gb", "disk_root_total_gb",
            "loadavg_1", "loadavg_5", "loadavg_15",
            "uptime_seconds", "services", "available",
        ):
            self.assertIn(key, snap)
        self.assertTrue(snap["available"])
        self.assertEqual(len(snap["services"]), len(UNIT_WHITELIST))

    @patch("core.services.system_status_service.subprocess.run")
    def test_snapshot_services_status(self, mock_run: MagicMock) -> None:
        def fake(cmd, **kw):
            m = MagicMock()
            m.stdout = "active\n" if cmd[2].endswith("dashboard.service") else "inactive\n"
            m.returncode = 0
            return m
        mock_run.side_effect = fake
        svc = SystemStatusService(checker=_checker_allow())
        snap = svc.get_snapshot("admin1")
        statuses = {s["unit"]: s["status"] for s in snap["services"]}
        self.assertEqual(
            statuses["security-ai-dashboard.service"], "active",
        )
        self.assertEqual(
            statuses["security-ai-event-reader.service"], "inactive",
        )

    @patch("core.services.system_status_service.psutil.cpu_percent",
           side_effect=RuntimeError("psutil kaputt"))
    def test_snapshot_fail_open_on_psutil_error(
        self, _mock: MagicMock,
    ) -> None:
        svc = SystemStatusService(checker=_checker_allow())
        snap = svc.get_snapshot("admin1")
        self.assertIsNone(snap["cpu_percent"])
        self.assertTrue(snap["available"])

    @patch("core.services.system_status_service.subprocess.run",
           side_effect=FileNotFoundError("kein systemctl"))
    def test_snapshot_fail_open_on_systemctl_error(
        self, _mock: MagicMock,
    ) -> None:
        svc = SystemStatusService(checker=_checker_allow())
        snap = svc.get_snapshot("admin1")
        for s in snap["services"]:
            self.assertEqual(s["status"], "unbekannt")

    def test_constructor_without_checker_raises(self) -> None:
        with self.assertRaises(SystemStatusOperationError):
            SystemStatusService(checker=None)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
