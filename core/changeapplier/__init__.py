"""ChangeApplier-Paket.

Bildet die Basis fuer den ChangeApplier, der
config_change-Objekte (aus dem Versioning) auf die
laufende Konfiguration anwendet.

Fail-closed: Import-Fehler muessen sofort sichtbar
sein, kein stilles Fallback.
"""

from .models import Change, ChangeApplier, ChangeState

__all__ = ["Change", "ChangeApplier", "ChangeState"]