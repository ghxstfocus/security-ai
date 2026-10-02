# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
apps/dashboard — Web-Dashboard fuer die Security AI.

Phase 3.6. create_app liegt in apps/dashboard/app.py.
Routes kommen in eigenen Modulen (routes_*.py).
"""
from apps.dashboard.app import create_app

__all__ = ["create_app"]
