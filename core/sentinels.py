# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Zentrale Sentinel-Konstanten.

Ein Sentinel ist ein Wert, der niemals ein echter Wert
sein kann. Er markiert "kein echter Wert vorhanden".

Heute nur FALLBACK_SENTINEL (Fritz!Box-Fallback-Name).
Weitere Sentinels gehoeren hier rein.
"""
from __future__ import annotations

FALLBACK_SENTINEL = "__FALLBACK__"

__all__ = ["FALLBACK_SENTINEL"]
