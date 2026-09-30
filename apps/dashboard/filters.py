"""
Jinja-Filter fuer das Dashboard (3.6.14).

Registrierung in apps/dashboard/app.py::create_app.

Filter formatieren, sie escapen NICHT. Jinja-Autoescape
greift auf den Rueckgabewert. Kein |safe an den
Aufrufstellen.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from core.risk.models import CATEGORY_LABELS

# RiskCategory-Wert -> Anzeige-Label. Quelle der Wahrheit:
# core/risk/models.py::CATEGORY_LABELS (Auflage 823, Punkt 31).
# Alias _SCORE_LABELS bleibt fuer bestehende Aufrufer.
_SCORE_LABELS = CATEGORY_LABELS


def format_ts(value: str | None) -> str:
    """
    ISO-8601-String -> "23.09.26 21:17 UTC".

    - Akzeptiert Strings mit Trennzeichen "T" oder " ".
    - Zeitzonen-Anteil wird verworfen, Ausgabe ist
      immer mit "UTC" markiert (Auflage 423).
    - Bei ungueltigem Input: Rohstring zurueck, kein
      Crash (Auflage 423).
    """
    if not isinstance(value, str) or not value:
        return "" if value is None else str(value)
    try:
        # Zuerst mit Zeitzone versuchen, sonst ohne.
        raw = value.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError:
            dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        dt = dt.astimezone(UTC)
        return dt.strftime("%d.%m.%y %H:%M UTC")
    except (ValueError, TypeError):
        return value


def format_score_label(category: str | None) -> str:
    """
    RiskCategory-Wert -> Anzeige-Label (Auflage 424).

    Unbekannte Kategorie -> Rohstring als Fallback.
    None -> "".
    """
    if category is None:
        return ""
    return _SCORE_LABELS.get(category, str(category))


def format_score(value: Any) -> str:
    """
    Score-Zahl -> "0.95" (Auflage 425).

    - Zwei Nachkommastellen, kein deutsches Komma.
    - Nicht-Zahlen: Rohstring zurueck.
    """
    try:
        return f"{float(value):.2f}"
    except (ValueError, TypeError):
        return "" if value is None else str(value)


_SOURCE_LABELS = {
    "devices": "Geraete",
    "whitelisted_devices": "Freigegebene Geraete",
    "changes": "Aenderungen",
    "approvals": "Freigaben",
    "principals": "Benutzer",
    "roles": "Rollen",
    "permissions": "Berechtigungen",
    "risk_assessments": "Alarme",
}


def format_source_label(source: str | None) -> str:
    """
    Suchquellen-Schluessel -> Anzeige-Label.

    Unbekannte Quelle -> Rohstring als Fallback.
    None -> "".
    """
    if source is None:
        return ""
    return _SOURCE_LABELS.get(source, str(source))
