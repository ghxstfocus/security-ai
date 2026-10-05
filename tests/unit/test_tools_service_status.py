# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Test fuer tools/service_status.py (Auflage 2015)."""
from __future__ import annotations

import unittest

from harness.tool_registry.tool import ToolArgumentValueError
from tools.service_status import service_status_run


class ServiceStatusValueErrorTests(unittest.TestCase):
    def test_service_status_empty_unit_is_value_error(self) -> None:
        with self.assertRaises(ToolArgumentValueError):
            service_status_run(unit="")


if __name__ == "__main__":
    unittest.main()
