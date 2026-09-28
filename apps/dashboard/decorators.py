"""
RBAC-Decorator, oeffentliche Pfade und Cookie-Name
fuer das Dashboard.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

PUBLIC_PATHS: frozenset[str] = frozenset({
    "/login",
    "/favicon.ico",
})

PUBLIC_PREFIXES: tuple[str, ...] = (
    "/static/",
)

SESSION_COOKIE_NAME = "security_ai_session"


F = TypeVar("F", bound=Callable[..., Any])


def require_permission(code: str) -> Callable[[F], F]:
    """
    Decorator: markiert eine View-Funktion mit der
    geforderten Permission. Setzt KEINEN Check, der
    kommt aus before_request.
    """
    def _wrap(fn: F) -> F:
        fn._required_permission = code
        return fn
    return _wrap


def is_public_path(path: str) -> bool:
    """True, wenn path in PUBLIC_PATHS oder unter einem
    PUBLIC_PREFIXES-Praefix liegt."""
    if path in PUBLIC_PATHS:
        return True
    for prefix in PUBLIC_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


__all__ = [
    "PUBLIC_PATHS",
    "PUBLIC_PREFIXES",
    "SESSION_COOKIE_NAME",
    "is_public_path",
    "require_permission",
]
