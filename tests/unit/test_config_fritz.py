# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer Fritz!Box-Getter in core/config.py.

Drei Getter: get_fritz_host, get_fritz_network_type,
get_fritz_credentials (fail closed).

Kein Netzwerkzugriff, keine echte Fritz!Box.
"""
from __future__ import annotations

import os
import unittest
from unittest import mock

from core.config import (
    DEFAULT_FRITZ_HOST,
    DEFAULT_FRITZ_NETWORK_TYPE,
    ConfigError,
    get_fritz_credentials,
    get_fritz_host,
    get_fritz_network_type,
)


class GetFritzHostTests(unittest.TestCase):
    def test_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FRITZ_HOST", None)
            self.assertEqual(get_fritz_host(), DEFAULT_FRITZ_HOST)

    def test_override(self) -> None:
        with mock.patch.dict(
            os.environ, {"FRITZ_HOST": "192.168.178.1"}, clear=False
        ):
            self.assertEqual(get_fritz_host(), "192.168.178.1")


class GetFritzNetworkTypeTests(unittest.TestCase):
    def test_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FRITZ_NETWORK_TYPE", None)
            self.assertEqual(
                get_fritz_network_type(), DEFAULT_FRITZ_NETWORK_TYPE
            )

    def test_override(self) -> None:
        with mock.patch.dict(
            os.environ, {"FRITZ_NETWORK_TYPE": "Gastnetz"}, clear=False
        ):
            self.assertEqual(get_fritz_network_type(), "Gastnetz")


class GetFritzCredentialsTests(unittest.TestCase):
    def test_ok(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"FRITZ_USERNAME": "admin", "FRITZ_PASSWORD": "geheim"},
            clear=False,
        ):
            user, pwd = get_fritz_credentials()
            self.assertEqual(user, "admin")
            self.assertEqual(pwd, "geheim")

    def test_missing_username(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FRITZ_USERNAME", None)
            os.environ["FRITZ_PASSWORD"] = "geheim"
            with self.assertRaises(ConfigError):
                get_fritz_credentials()

    def test_missing_password(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ["FRITZ_USERNAME"] = "admin"
            os.environ.pop("FRITZ_PASSWORD", None)
            with self.assertRaises(ConfigError):
                get_fritz_credentials()

    def test_both_missing(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FRITZ_USERNAME", None)
            os.environ.pop("FRITZ_PASSWORD", None)
            with self.assertRaises(ConfigError):
                get_fritz_credentials()

    def test_empty_string_counts_as_missing(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"FRITZ_USERNAME": "", "FRITZ_PASSWORD": "geheim"},
            clear=False,
        ), self.assertRaises(ConfigError):
            get_fritz_credentials()


if __name__ == "__main__":
    unittest.main()
