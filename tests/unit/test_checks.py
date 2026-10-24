# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit-Tests fuer core.checks."""

from __future__ import annotations

import pytest

from core.checks import check_port, check_port_count, check_port_list, check_port_range


@pytest.mark.parametrize("port", [1, 2, 80, 443, 65534, 65535])
def test_check_port_valid(port: int) -> None:
    assert check_port(port) is True


@pytest.mark.parametrize("port", [0, -1, 65536, 100000, -65535])
def test_check_port_out_of_range(port: int) -> None:
    assert check_port(port) is False


@pytest.mark.parametrize("port", [True, False])
def test_check_port_bool(port: bool) -> None:
    assert check_port(port) is False


@pytest.mark.parametrize("port", ["80", "", "abc", None, 80.0, [], {}])
def test_check_port_wrong_type(port: object) -> None:
    assert check_port(port) is False


def test_check_port_range_valid() -> None:
    assert check_port_range(80, 1, 100) is True
    assert check_port_range(1, 1, 1) is True
    assert check_port_range(65535, 1, 65535) is True


def test_check_port_range_outside() -> None:
    assert check_port_range(80, 100, 200) is False
    assert check_port_range(80, 1, 79) is False


def test_check_port_range_min_greater_max() -> None:
    assert check_port_range(80, 100, 1) is False


def test_check_port_range_invalid_port() -> None:
    assert check_port_range(0, 0, 100) is False
    assert check_port_range(65536, 1, 65535) is False
    assert check_port_range(True, 1, 100) is False
    assert check_port_range("80", 1, 100) is False
    assert check_port_range(None, 1, 100) is False


def test_check_port_range_invalid_bounds() -> None:
    assert check_port_range(80, True, 100) is False
    assert check_port_range(80, 1, False) is False
    assert check_port_range(80, "1", 100) is False
    assert check_port_range(80, 1, None) is False


def test_check_port_list_empty() -> None:
    assert check_port_list([], 1, 100) == []


def test_check_port_list_all_valid() -> None:
    assert check_port_list([1, 50, 100], 1, 100) == [1, 50, 100]


def test_check_port_list_all_invalid() -> None:
    assert check_port_list([0, 101, 65536], 1, 100) == []


def test_check_port_list_mixed() -> None:
    assert check_port_list([0, 1, 50, 101, 100], 1, 100) == [1, 50, 100]


def test_check_port_list_bounds() -> None:
    assert check_port_list([1, 100], 1, 100) == [1, 100]
    assert check_port_list([0, 101], 1, 100) == []


def test_check_port_list_preserves_order() -> None:
    assert check_port_list([100, 1, 50], 1, 100) == [100, 1, 50]


def test_check_port_list_invalid_entries() -> None:
    assert check_port_list([True, "80", None, 80.0, 80], 1, 100) == [80]


def test_check_port_list_invalid_bounds() -> None:
    assert check_port_list([80], True, 100) == []
    assert check_port_list([80], 1, False) == []
    assert check_port_list([80], "1", 100) == []
    assert check_port_list([80], 1, None) == []


def test_check_port_list_non_list_input() -> None:
    assert check_port_list("80", 1, 100) == []
    assert check_port_list(None, 1, 100) == []


def test_check_port_count_empty() -> None:
    assert check_port_count([], 1, 100) == 0


def test_check_port_count_all_valid() -> None:
    assert check_port_count([1, 50, 100], 1, 100) == 3


def test_check_port_count_all_invalid() -> None:
    assert check_port_count([0, 101, 65536], 1, 100) == 0


def test_check_port_count_mixed() -> None:
    assert check_port_count([0, 1, 50, 101, 100], 1, 100) == 3


def test_check_port_count_invalid_entries() -> None:
    assert check_port_count([True, "80", None, 80.0, 80], 1, 100) == 1


def test_check_port_count_invalid_bounds() -> None:
    assert check_port_count([80], True, 100) == 0
    assert check_port_count([80], 1, False) == 0
    assert check_port_count([80], "1", 100) == 0
    assert check_port_count([80], 1, None) == 0


def test_check_port_count_non_list_input() -> None:
    assert check_port_count("80", 1, 100) == 0
    assert check_port_count(None, 1, 100) == 0
