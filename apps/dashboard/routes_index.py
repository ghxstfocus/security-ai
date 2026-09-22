"""
Dashboard-Startseite.

Kategorie 3 (Route, RBAC, Template).

Auflage 290.
"""
from __future__ import annotations

from flask import Flask, render_template

from apps.dashboard.decorators import require_permission


def register_index_routes(app: Flask) -> None:
    @app.route("/", methods=["GET"])
    @require_permission("device.read")
    def index():
        return render_template(
            "index.html",
            page_title="Dashboard",
        )


__all__ = ["register_index_routes"]
