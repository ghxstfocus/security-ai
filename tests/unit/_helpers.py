"""
Test-Helper fuer Unit-Tests.

Kein pytest-Fixture-Modul. Reine Funktionen, die
in Tests und Fixtures direkt aufgerufen werden
koennen.
"""
from __future__ import annotations

from apps.dashboard.decorators import SESSION_COOKIE_NAME


def set_session_cookie(client, value):
    """
    Setzt das Session-Cookie mit den Produktions-Flags.

    Helper, keine Fixture. Grund: Fixtures rufen ihn
    innerhalb anderer Fixtures auf (client,
    viewer_client).
    """
    client.set_cookie(
        SESSION_COOKIE_NAME, value,
        domain="localhost",
        secure=True, httponly=True, samesite="Strict",
    )
    return client


__all__ = ["set_session_cookie"]
