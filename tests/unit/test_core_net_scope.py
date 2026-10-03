# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer core/net/scope.py (Punkt 58, Schritt 1a)."""
from __future__ import annotations

import unittest

from core.net.scope import check_target_allowed, is_in_scope
from harness.tool_registry.tool import ToolError


class CheckTargetAllowedTests(unittest.TestCase):
    def test_check_target_allowed_in_scope(self) -> None:
        check_target_allowed("127.0.0.1")
        check_target_allowed("192.168.178.10")
        check_target_allowed("10.0.0.1")

    def test_check_target_allowed_out_of_scope(self) -> None:
        with self.assertRaises(ToolError):
            check_target_allowed("8.8.8.8")
        with self.assertRaises(ToolError):
            check_target_allowed("1.1.1.1")

class IsInScopeTests(unittest.TestCase):
    def test_is_in_scope_localhost(self) -> None:
        self.assertTrue(is_in_scope("127.0.0.1"))
        self.assertTrue(is_in_scope("localhost"))
        self.assertFalse(is_in_scope("8.8.8.8"))
