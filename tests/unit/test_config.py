"""
Tests fuer core/config.py.

Schwerpunkte:
- get_secret_key: Fail closed (fehlt, zu kurz).
- Byte-Laenge, nicht Zeichen-Laenge.
- Lokale Fixture, kein autouse, kein conftest.

Auflage 41: 31-Byte-Grenztest (off-by-one).
"""
from __future__ import annotations

import pytest

from core.config import (
    SECRET_KEY_MIN_BYTES,
    ConfigError,
    get_secret_key,
)

# ---------------------------------------------------------------------- #
# Fixtures
# ---------------------------------------------------------------------- #

@pytest.fixture()
def secret_key(monkeypatch: pytest.MonkeyPatch) -> str:
    value = "x" * 48
    monkeypatch.setenv("SECRET_KEY", value)
    return value


# ---------------------------------------------------------------------- #
# get_secret_key
# ---------------------------------------------------------------------- #

def test_get_secret_key_ok(secret_key: str) -> None:
    assert get_secret_key() == secret_key


def test_get_secret_key_missing_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(ConfigError):
        get_secret_key()


def test_get_secret_key_empty_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECRET_KEY", "")
    with pytest.raises(ConfigError):
        get_secret_key()


def test_get_secret_key_too_short_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECRET_KEY", "kurz")
    with pytest.raises(ConfigError):
        get_secret_key()


def test_get_secret_key_exactly_min_bytes_ok(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = "a" * SECRET_KEY_MIN_BYTES
    monkeypatch.setenv("SECRET_KEY", value)
    assert get_secret_key() == value


def test_get_secret_key_mehrbyte_zu_kurz(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 15 Zeichen * 2 Byte (UTF-8) = 30 Byte -> zu kurz.
    monkeypatch.setenv("SECRET_KEY", "\u00e4" * 15)
    with pytest.raises(ConfigError):
        get_secret_key()


def test_get_secret_key_mehrbyte_31_bytes_zu_kurz(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 15 * 2 Byte + 1 ASCII = 31 Byte -> zu kurz (Auflage 41).
    value = "\u00e4" * 15 + "a"
    monkeypatch.setenv("SECRET_KEY", value)
    with pytest.raises(ConfigError):
        get_secret_key()


def test_get_secret_key_mehrbyte_ok(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 16 Zeichen * 2 Byte = 32 Byte -> ok.
    value = "\u00e4" * 16
    monkeypatch.setenv("SECRET_KEY", value)
    assert get_secret_key() == value


# ---------------------------------------------------------------------- #
# Konstante
# ---------------------------------------------------------------------- #

def test_secret_key_min_bytes_is_32() -> None:
    assert SECRET_KEY_MIN_BYTES == 32
