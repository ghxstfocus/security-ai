# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

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
    get_guest_network_prefix,
    get_ollama_base_url,
    get_secret_key,
    resolve_network_type,
    validate_ollama_base_url,
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


def test_validate_ollama_file_scheme_raises() -> None:
    with pytest.raises(ConfigError):
        validate_ollama_base_url("file:///etc/passwd")


def test_validate_ollama_external_host_raises() -> None:
    with pytest.raises(ConfigError):
        validate_ollama_base_url("http://evil.example.com")


def test_validate_ollama_leer_raises() -> None:
    with pytest.raises(ConfigError):
        validate_ollama_base_url("")


def test_validate_ollama_loopback_ok() -> None:
    url = "http://127.0.0.1:11434"
    assert validate_ollama_base_url(url) == url


def test_validate_ollama_localhost_ok() -> None:
    url = "http://localhost:11434"
    assert validate_ollama_base_url(url) == url


def test_validate_ollama_https_loopback_ok() -> None:
    url = "https://127.0.0.1:11434"
    assert validate_ollama_base_url(url) == url


def test_validate_ollama_lan_host_raises() -> None:
    with pytest.raises(ConfigError):
        validate_ollama_base_url("http://192.168.178.50:11434")


def test_get_ollama_base_url_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_BASE_URL", "file:///etc/passwd")
    with pytest.raises(ConfigError):
        get_ollama_base_url()


# ------------------------------------------------------------------ #
# resolve_network_type (Punkt 67)
# ------------------------------------------------------------------ #

def test_resolve_gastnetz():
    assert resolve_network_type("192.168.189.5") == "Gastnetz"

def test_resolve_hauptnetz():
    assert resolve_network_type("192.168.178.5") == "Hauptnetz"

def test_resolve_none():
    assert resolve_network_type(None) == "Unbekannt"

def test_resolve_leer():
    assert resolve_network_type("") == "Unbekannt"

def test_resolve_ungueltige_ip():
    assert resolve_network_type("nicht-eine-ip") == "Unbekannt"

def test_resolve_kein_extern():
    assert resolve_network_type("8.8.8.8") != "Extern"

def test_guest_prefix_default():
    assert get_guest_network_prefix() == "192.168.189.0/24"

def test_guest_prefix_env(monkeypatch):
    monkeypatch.setenv(
        "GUEST_NETWORK_PREFIX", "10.99.0.0/16",
    )
    assert get_guest_network_prefix() == "10.99.0.0/16"

def test_resolve_mit_env_prefix(monkeypatch):
    monkeypatch.setenv(
        "GUEST_NETWORK_PREFIX", "10.99.0.0/16",
    )
    assert resolve_network_type("10.99.1.5") == "Gastnetz"
    assert resolve_network_type("192.168.189.5") == "Hauptnetz"
