"""
Zentrale Konfiguration aus .env.

Standardlib-Loader, kein python-dotenv.

Konvention:
- .env im Projekt-Root, Format KEY=VALUE.
- Werte landen per os.environ.setdefault in der Umgebung.
- Bereits gesetzte Umgebungsvariablen gewinnen (Tests/CI).
- Werte werden NICHT gecacht; Getter lesen live aus os.environ.
  reset_cache() ist fuer Tests da, die .env neu laden wollen.
"""
from __future__ import annotations

import os
from pathlib import Path

DEFAULT_ENV_PATH = ".env"

DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.2:3b"
DEFAULT_MODEL_LARGE = "qwen2.5:7b"

_loaded_paths: set[str] = set()


# ---------------------------------------------------------------------- #
# Fehler
# ---------------------------------------------------------------------- #

class ConfigError(RuntimeError):
    """Fehlende oder ungueltige Konfiguration (fail closed)."""


SECRET_KEY_MIN_BYTES = 32


# ---------------------------------------------------------------------- #
# .env-Loader
# ---------------------------------------------------------------------- #

def load_env(path: str | Path = DEFAULT_ENV_PATH) -> None:
    """
    Liest KEY=VALUE-Zeilen aus .env und setzt sie per
    os.environ.setdefault.

    Regeln:
    - Leere Zeilen und Zeilen, die mit '#' beginnen, werden ignoriert.
    - Nur KEY=VALUE (kein 'export', kein Quoting).
    - Whitespace um Key und Value wird getrimmt.
    - Fehlende Datei -> kein Fehler (Konvention: .env ist optional).
    - Bereits gesetzte Umgebungsvariablen werden nicht ueberschrieben.
    """
    p = Path(path)
    if not p.exists():
        return
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError:
        return

    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "=" not in s:
            continue
        key, _, value = s.partition("=")
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        # Optionales Quoting entfernen
        if len(value) >= 2 and value[0] == value[-1] and \
                value[0] in ("'", '"'):
            value = value[1:-1]
        os.environ.setdefault(key, value)

    _loaded_paths.add(str(p.resolve()))


def reset_cache() -> None:
    """
    Setzt den internen Lade-Marker zurueck.

    Wichtig fuer Tests: sie koennen .env neu einlesen, ohne dass
    ein bereits geladener Pfad als 'schon geladen' gilt.
    Die tatsaechlichen os.environ-Werte werden NICHT geloescht.
    """
    _loaded_paths.clear()


# ---------------------------------------------------------------------- #
# Getter
# ---------------------------------------------------------------------- #

def get_ollama_base_url() -> str:
    return os.environ.get("OLLAMA_BASE_URL", DEFAULT_OLLAMA_BASE_URL)


def get_model_default() -> str:
    return os.environ.get("SECURITY_AI_MODEL", DEFAULT_MODEL)


def get_model_large() -> str:
    return os.environ.get("SECURITY_AI_MODEL_LARGE", DEFAULT_MODEL_LARGE)


def get_secret_key() -> str:
    """
    Liest SECRET_KEY aus der Umgebung.

    Fail closed:
    - Variable fehlt -> ConfigError.
    - Wert kuerzer als SECRET_KEY_MIN_BYTES (in Byte,
      UTF-8-kodiert) -> ConfigError.

    Kein Default, kein Fallback auf os.urandom.
    Byte-Laenge, nicht Zeichen-Laenge (kryptographische
    Groesse).

    Erzeugen:
        python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
    """
    value = os.environ.get("SECRET_KEY")
    if not value:
        raise ConfigError(
            "SECRET_KEY fehlt in der Umgebung (.env). "
            "Erzeugen mit: python3 -c 'import secrets; "
            "print(secrets.token_urlsafe(48))'"
        )
    n_bytes = len(value.encode("utf-8"))
    if n_bytes < SECRET_KEY_MIN_BYTES:
        raise ConfigError(
            f"SECRET_KEY zu kurz ({n_bytes} Byte, "
            f"mindestens {SECRET_KEY_MIN_BYTES}). "
            "Empfehlung: secrets.token_urlsafe(48)"
        )
    return value


__all__ = [
    "DEFAULT_ENV_PATH",
    "DEFAULT_MODEL",
    "DEFAULT_MODEL_LARGE",
    "DEFAULT_OLLAMA_BASE_URL",
    "SECRET_KEY_MIN_BYTES",
    "ConfigError",
    "get_model_default",
    "get_model_large",
    "get_ollama_base_url",
    "get_secret_key",
    "load_env",
    "reset_cache",
]
