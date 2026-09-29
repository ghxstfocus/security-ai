"""
Dashboard-Route fuer Einstellungen.

Kategorie 3: read-only Konfigurationsanzeige, role.manage.
Kein SECRET_KEY, kein os.environ-Dump, kein Existenz-Check.

- GET /settings     role.manage

Kein POST, kein CSRF, kein Formular.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any


from flask import Flask, current_app, render_template

from apps.dashboard.decorators import require_permission
from core.config import (
    get_model_default,
    get_model_large,
    get_ollama_base_url,
)


def _snapshot() -> dict:
    cfg = current_app.config

    def _val(key: str, fallback: Any = "—") -> Any:
        v = cfg.get(key, None)
        if v is None or v == "":
            return fallback
        return v

    lifetime = cfg.get("PERMANENT_SESSION_LIFETIME", None)
    if isinstance(lifetime, timedelta):
        lifetime_str = str(int(lifetime.total_seconds())) + " s"
    elif lifetime is None:
        lifetime_str = "—"
    else:
        lifetime_str = str(lifetime)

    return {
        "db_path": _val("DB_PATH"),
        "migrations_dir": _val("MIGRATIONS_DIR"),
        "audit_base_dir": _val("AUDIT_BASE_DIR"),
        "debug": _val("DEBUG"),
        "testing": _val("TESTING"),
        "max_content_length": _val("MAX_CONTENT_LENGTH"),
        "ollama_base_url": get_ollama_base_url(),
        "model_default": get_model_default(),
        "model_large": get_model_large(),
        "cookie_httponly": _val("SESSION_COOKIE_HTTPONLY"),
        "cookie_secure": _val("SESSION_COOKIE_SECURE"),
        "cookie_samesite": _val("SESSION_COOKIE_SAMESITE"),
        "session_lifetime": lifetime_str,
    }


def register_settings_routes(app: Flask) -> None:
    @app.route("/settings", methods=["GET"])
    @require_permission("role.manage")
    def settings_view() -> str:
        return render_template(
            "settings.html",
            page_title="Einstellungen",
            cfg=_snapshot(),
        )


__all__ = ["register_settings_routes"]
