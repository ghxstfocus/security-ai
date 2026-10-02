# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""WSGI-Einstiegspunkt fuer gunicorn (Punkt 16).

Nur die App-Instanz, kein Dev-Start. Der Dev-Start
bleibt in apps/dashboard/app.py (__main__).
"""
from __future__ import annotations

from apps.dashboard.app import create_app

app = create_app()


__all__ = ["app"]
