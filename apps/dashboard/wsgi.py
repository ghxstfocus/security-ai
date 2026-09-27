"""WSGI-Einstiegspunkt fuer gunicorn (Punkt 16).

Nur die App-Instanz, kein Dev-Start. Der Dev-Start
bleibt in apps/dashboard/app.py (__main__).
"""
from __future__ import annotations

from apps.dashboard.app import create_app


app = create_app()


__all__ = ["app"]
