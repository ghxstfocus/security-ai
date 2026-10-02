# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""HTTP-Redirect-Helper (CSP-neutral, Response-Typ).

Grund (Auflage 1657, B1a):
redirect() liefert werkzeug.wrappers.Response, das ist
Oberklasse von flask.wrappers.Response. mypy sieht den
Konflikt (Oberklasse passt nicht in Subklassen-Slot).
cast() dokumentiert die Zusicherung, dass zur Laufzeit
passt, was mypy ohne cast nicht sieht.

Ein Ort fuer alle Route-Handler (B1a: 3 Aufrufe,
B1b: 12 Aufrufe).
"""
from __future__ import annotations

from typing import cast

from flask import Response, redirect


def safe_redirect(url: str, code: int = 302) -> Response:
    """redirect() mit cast auf flask.Response.

    url: Ziel-URL. Kein User-Input ohne vorherige
         Validierung (siehe _safe_next in auth.py).
    code: HTTP-Status, Default 302.
    """
    return cast(Response, redirect(url, code=code))


__all__ = ["safe_redirect"]
