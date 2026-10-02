"""
Klartext-Begruendung fuer Alarme (Punkt 79).

Deterministisch, kein LLM. Regel-ID -> Klartext.
Konsistent zu CATEGORY_LABELS (core/risk/models.py).
"""
from __future__ import annotations

RULE_TEMPLATES: dict[str, str] = {
    "unknown_device":
        "Unbekanntes Geraet im Hauptnetz",
    "unknown_device_persistent":
        "Unbekanntes Geraet seit ueber einer Stunde "
        "im Hauptnetz",
    "network_change":
        "Netz-Wechsel ins Hauptnetz",
    "mac_change":
        "MAC-Wechsel bei gleichem Geraetenamen",
    "device_flapping":
        "Geraet wechselt mehrfach zwischen online "
        "und offline",
    "port_scan":
        "Port-Scan erkannt",
}


def explain_alert(
    rule_id: str | None,
    reasons: list[str] | None = None,
) -> str:
    """Liefert den Klartext zur Regel-ID.

    Fallback: "Regel: <rule_id>".
    reasons werden als Klammer-Zusatz angehaengt.
    """
    if not rule_id:
        base = "Regel unbekannt"
    else:
        base = RULE_TEMPLATES.get(rule_id, f"Regel: {rule_id}")

    rs = [r for r in (reasons or []) if isinstance(r, str) and r]
    if not rs:
        return base

    if len(rs) > 2:
        detail = ", ".join(rs[:2]) + f" und {len(rs) - 2} weitere"
    else:
        detail = ", ".join(rs)
    return f"{base} ({detail})"


__all__ = ["RULE_TEMPLATES", "explain_alert"]
