"""
Service-Schicht.

Enthaelt ServiceError als Basis fuer alle
Service-Fehler. Konkrete Service-Fehler bleiben
in ihren Modulen (access_service.py etc.).
"""
from __future__ import annotations


class ServiceError(RuntimeError):
    """Basis fuer alle Service-Fehler."""


__all__ = ["ServiceError"]
