# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Service-Fehlerklassen.

Trennung:
- ServiceError    = fachlicher/Format-Fehler -> 4xx.
                    Ungueltige Eingabe, fehlende Pflichtfelder,
                    ungueltiges Format, RBAC-relevante
                    Validierungsfehler.
- OperationError  = Betriebsfehler -> 5xx.
                    DB-Fehler, Audit-Fehler, unerwartete
                    Laufzeitfehler. Diese duerfen NICHT als
                    4xx maskiert werden, sonst sieht der Nutzer
                    "dein Request war falsch", obwohl das
                    System gestoert ist.

Beide erben direkt von RuntimeError. OperationError ist
bewusst NICHT Subklasse von ServiceError, damit ein
`except ServiceError` im Route-Handler den Betriebsfehler
NICHT faengt und der globale 500-Handler greifen kann.
"""
from __future__ import annotations


class ServiceError(RuntimeError):
    """Basis fuer alle fachlichen Service-Fehler (4xx)."""


class OperationError(RuntimeError):
    """Basis fuer alle Betriebsfehler im Service (5xx)."""


__all__ = [
    "OperationError",
    "ServiceError",
]
