"""
Service-Schicht.

Oeffentliches Interface: ServiceError und OperationError.
Konkrete Fehlerklassen (AccessServiceError, ChangeServiceError,
ChangeOperationError, ...) bleiben in ihren Modulen.
"""
from __future__ import annotations

from core.services.errors import OperationError, ServiceError


__all__ = [
    "OperationError",
    "ServiceError",
]
