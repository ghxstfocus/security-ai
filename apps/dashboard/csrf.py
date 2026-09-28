"""
CSRF-Helfer fuer das Dashboard.

Synchronizer-Token-Verfahren:
- Token in flask.session["_csrf_token"].
- Vergleich mit hmac.compare_digest.
- Rotation nach Login (Auflage 115).
"""
from __future__ import annotations

import hmac
import secrets
from typing import Any

_CSRF_KEY = "_csrf_token"
_TOKEN_BYTES = 32


def get_or_create(session: Any) -> str:
    token = session.get(_CSRF_KEY)
    if not isinstance(token, str) or not token:
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        session[_CSRF_KEY] = token
    return token


def rotate(session: Any) -> str:
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    session[_CSRF_KEY] = token
    return token


def validate(submitted: Any, expected: Any) -> bool:
    if not isinstance(submitted, str) or not submitted:
        return False
    if not isinstance(expected, str) or not expected:
        return False
    try:
        return hmac.compare_digest(submitted, expected)
    except (TypeError, ValueError):
        return False


__all__ = ["get_or_create", "rotate", "validate"]
