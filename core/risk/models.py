"""
Datenmodelle der Risk Engine.

Ein RiskAssessment ist das Ergebnis der Bewertung eines Events.
Es ist unveraenderlich und traegt neben dem Score die angewendeten
Modifier und Klartext-Gruende — damit die Bewertung auditierbar
bleibt und ein LLM spaeter nur erklaeren, nicht bewerten muss.

Die Risk Engine ist deterministisch: kein DB-Zugriff waehrend
evaluate. Alle externen Daten (Inventory, Whitelist) muessen vorher
in den RiskContext geladen werden.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class RiskRuleError(Exception):
    """Fehler in einer Risk-Regel (unbekannter when-Name, ungueltige Config)."""


class RiskCategory(str, Enum):
    """Grobe Einstufung abgeleitet aus dem Score."""
    EVENT = "EVENT"
    ANOMALY = "ANOMALY"
    SUSPICION = "SUSPICION"
    SECURITY_ALERT = "SECURITY_ALERT"
    CONFIRMED = "CONFIRMED"

    def __str__(self) -> str:  # pragma: no cover
        return self.value


# Anzeige-Labels pro RiskCategory-Wert (Auflage 823, Punkt 31).
# Eine Quelle der Wahrheit fuer Dashboard (filters.py) und
# ChatService (_answer_fact). Wortlaut deckungsgleich mit
# der bestehenden Badge-Zuordnung in alerts.html (Auflage 424).
CATEGORY_LABELS: dict[str, str] = {
    "EVENT": "Info",
    "ANOMALY": "Hinweis",
    "SUSPICION": "Warnung",
    "SECURITY_ALERT": "Alarm",
    "CONFIRMED": "Kritisch",
}


# Default-Schwellen. In rules.yaml ueberschreibbar.
DEFAULT_THRESHOLDS: dict[str, float] = {
    "anomaly": 0.2,
    "suspicion": 0.4,
    "security_alert": 0.6,
    "confirmed": 0.8,
}


def clamp_score(score: float) -> float:
    """Klemmt einen Score auf [0.0, 1.0]."""
    if score < 0.0:
        return 0.0
    if score > 1.0:
        return 1.0
    return float(score)


def score_to_category(
    score: float,
    thresholds: dict[str, float] | None = None,
) -> RiskCategory:
    """
    Leitet die RiskCategory aus dem Score ab.

    Default-Schwellen: 0.2 / 0.4 / 0.6 / 0.8.
    Alle Schwellen muessen aufsteigend sein, sonst RiskRuleError.
    """
    th = dict(DEFAULT_THRESHOLDS)
    if thresholds:
        th.update(thresholds)

    a = th["anomaly"]
    s = th["suspicion"]
    sa = th["security_alert"]
    c = th["confirmed"]
    if not (a <= s <= sa <= c):
        raise RiskRuleError(
            f"Schwellen nicht aufsteigend: {a} {s} {sa} {c}"
        )

    if score >= c:
        return RiskCategory.CONFIRMED
    if score >= sa:
        return RiskCategory.SECURITY_ALERT
    if score >= s:
        return RiskCategory.SUSPICION
    if score >= a:
        return RiskCategory.ANOMALY
    return RiskCategory.EVENT


@dataclass(frozen=True)
class RiskAssessment:
    """
    Ergebnis der Risk-Bewertung eines Events.

    - event_id:   Referenz auf das bewertete Event
    - rule_id:    welche Risk-Regel das Assessment erzeugt hat
    - score:      geklemmt auf [0.0, 1.0]
    - category:   aus Score abgeleitet
    - base:       Basiswert der Regel (vor Modifiern)
    - modifiers:  Liste (name, wert) der angewendeten Modifier
    - reasons:    Klartext-Gruende (auditierbar, LLM-freundlich)
    - timestamp:  wann das Assessment erstellt wurde (UTC)
    """
    event_id: str
    rule_id: str
    score: float
    category: RiskCategory
    base: float
    modifiers: list[tuple[str, float]] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    def __post_init__(self) -> None:
        if not (0.0 <= self.score <= 1.0):
            raise ValueError(f"score ausserhalb [0,1]: {self.score}")
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp muss timezone-aware sein")

    @property
    def modifier_total(self) -> float:
        return sum(v for _n, v in self.modifiers)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "rule_id": self.rule_id,
            "score": self.score,
            "category": self.category.value,
            "base": self.base,
            "modifiers": [list(m) for m in self.modifiers],
            "reasons": list(self.reasons),
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(frozen=True)
class RiskContext:
    """
    Kontext fuer die Risk-Bewertung.

    - now:          aktueller Zeitstempel (UTC, Wall-Clock)
    - network_id:   Netzwerk, in dem das Event auftrat
    - inventory:    optionale vorher geladene Inventory-Daten.
                    Empfohlen: dict mit Keys "devices" (set[str] von
                    identifiern) und "whitelist" (set[str]). Kein DB-Zugriff
                    in evaluate — alles muss hier drinstehen.
    - config:       Regel-spezifische Config aus rules.yaml
    """
    now: datetime
    network_id: str
    inventory: dict[str, Any] | None = None
    config: dict[str, Any] = field(default_factory=dict)

    def is_in_inventory(self, identifier: str) -> bool:
        if not self.inventory:
            return False
        devices = self.inventory.get("devices") or set()
        return identifier in devices

    def is_whitelisted(self, identifier: str) -> bool:
        if not self.inventory:
            return False
        wl = self.inventory.get("whitelist") or set()
        return identifier in wl


__all__ = [
    "DEFAULT_THRESHOLDS",
    "RiskAssessment",
    "RiskCategory",
    "RiskContext",
    "RiskRuleError",
    "clamp_score",
    "score_to_category",
]
