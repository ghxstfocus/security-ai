"""
Risk Engine.

Laedt core/risk/rules.yaml, wendet pro Event-Typ die passenden Regeln
an und liefert ein RiskAssessment.

Deterministisch: kein DB-Zugriff. Alle externen Daten (Inventory,
Whitelist) muessen vorher im RiskContext liegen.

Fail closed:
  - fehlender "default"-Block in rules.yaml -> RiskRuleError
  - unbekannter "when"-Name -> RiskRuleError
Predicates selbst werfen nie; fehlende Felder im event.data -> False.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    import yaml  # PyYAML
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "PyYAML wird gebraucht. Installieren mit: apt install python3-yaml"
    ) from exc

from core.events.event import Event
from core.risk.models import (
    RiskAssessment,
    RiskContext,
    RiskRuleError,
    clamp_score,
    score_to_category,
)


Predicate = Callable[[Event, RiskContext], bool]


# ---------------------------------------------------------------------- #
# Predicates
# ---------------------------------------------------------------------- #

def _data(event: Event, key: str) -> Any:
    """Liest event.data[key], None wenn nicht vorhanden."""
    return event.data.get(key)


def _pred_hauptnetz(event: Event, context: RiskContext) -> bool:
    return _data(event, "network_type") == "Hauptnetz"


def _pred_gastnetz(event: Event, context: RiskContext) -> bool:
    return _data(event, "network_type") == "Gastnetz"


def _pred_extern(event: Event, context: RiskContext) -> bool:
    return _data(event, "network_type") == "Extern"


def _pred_nachts(event: Event, context: RiskContext) -> bool:
    """22:00 bis 05:00 Uhr (lokal, aber wir nehmen event.timestamp als Basis)."""
    ts = event.timestamp
    if ts.tzinfo is None:
        return False
    h = ts.hour
    return h >= 22 or h < 5


def _pred_wochenende(event: Event, context: RiskContext) -> bool:
    ts = event.timestamp
    if ts.tzinfo is None:
        return False
    return ts.weekday() >= 5  # 5 = Samstag, 6 = Sonntag


def _pred_not_in_inventory(event: Event, context: RiskContext) -> bool:
    identifier = _data(event, "identifier")
    if not identifier or not isinstance(identifier, str):
        return False
    return not context.is_in_inventory(identifier)


def _pred_first_seen(event: Event, context: RiskContext) -> bool:
    """
    True, wenn das Event als "erstes Auftreten" markiert ist.

    Das Feld data["first_seen"] wird vom Orchestrator gesetzt, bevor
    die Risk Engine laeuft. Deterministisch, replay-faehig.
    """
    return _data(event, "first_seen") is True


def _pred_is_whitelisted(event: Event, context: RiskContext) -> bool:
    identifier = _data(event, "identifier")
    if not identifier or not isinstance(identifier, str):
        return False
    return context.is_whitelisted(identifier)


def _pred_many_ports(event: Event, context: RiskContext) -> bool:
    return event.event_type == "port_scan" and _data(event, "kind") == "port_scan"


def _pred_many_ips(event: Event, context: RiskContext) -> bool:
    return event.event_type == "port_scan" and _data(event, "kind") == "network_scan"


def _pred_brute_force(event: Event, context: RiskContext) -> bool:
    return event.event_type == "port_scan" and _data(event, "kind") == "brute_force"


PREDICATES: dict[str, Predicate] = {
    "hauptnetz": _pred_hauptnetz,
    "gastnetz": _pred_gastnetz,
    "extern": _pred_extern,
    "nachts": _pred_nachts,
    "wochenende": _pred_wochenende,
    "not_in_inventory": _pred_not_in_inventory,
    "first_seen": _pred_first_seen,
    "is_whitelisted": _pred_is_whitelisted,
    "many_ports": _pred_many_ports,
    "many_ips": _pred_many_ips,
    "brute_force": _pred_brute_force,
}


# ---------------------------------------------------------------------- #
# Engine
# ---------------------------------------------------------------------- #

class RiskEngine:
    """
    Laedt rules.yaml und bewertet Events.

    rules.yaml-Format:

        thresholds:
          anomaly: 0.2
          suspicion: 0.4
          security_alert: 0.6
          confirmed: 0.8

        default:
          rule_id: default
          base: 0.1
          modifiers: []

        rules:
          unknown_device:
            rule_id: unknown_device
            base: 0.5
            modifiers:
              - when: hauptnetz
                add: 0.2
                reason: "im Hauptnetz"
              - when: not_in_inventory
                add: 0.2
                reason: "nicht im Inventory"
              - when: nachts
                add: 0.1
                reason: "nachts (22-05)"

    In evaluate wird zuerst "rules[event_type]" gesucht. Fehlt es,
    greift "default". Der "default"-Block ist Pflicht.
    """

    def __init__(self, rules_path: Path | str = "core/risk/rules.yaml") -> None:
        self._path = Path(rules_path)
        self._thresholds: dict[str, float] = {}
        self._default: dict[str, Any] = {}
        self._rules: dict[str, dict[str, Any]] = {}
        self._load()

    # ------------------------------------------------------------------ #
    # Laden + Validieren
    # ------------------------------------------------------------------ #

    def _load(self) -> None:
        if not self._path.exists():
            raise RiskRuleError(f"rules.yaml fehlt: {self._path}")

        with self._path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}

        if not isinstance(data, dict):
            raise RiskRuleError("rules.yaml: top-level muss ein Mapping sein")

        self._thresholds = data.get("thresholds") or {}
        self._default = data.get("default") or {}
        self._rules = data.get("rules") or {}

        if not self._default:
            raise RiskRuleError(
                "rules.yaml: 'default'-Block ist Pflicht (fuer unbekannte Event-Typen)"
            )
        self._validate_rule("default", self._default)
        for event_type, rule in self._rules.items():
            if not isinstance(event_type, str):
                raise RiskRuleError(f"rules.yaml: Regelname kein String: {event_type!r}")
            self._validate_rule(event_type, rule)

    def _validate_rule(self, name: str, rule: dict[str, Any]) -> None:
        if not isinstance(rule, dict):
            raise RiskRuleError(f"Regel {name!r}: muss ein Mapping sein")
        if "base" not in rule:
            raise RiskRuleError(f"Regel {name!r}: 'base' fehlt")
        try:
            float(rule["base"])
        except (TypeError, ValueError) as exc:
            raise RiskRuleError(
                f"Regel {name!r}: 'base' ist keine Zahl: {rule['base']!r}"
            ) from exc

        mods = rule.get("modifiers", [])
        if not isinstance(mods, list):
            raise RiskRuleError(f"Regel {name!r}: 'modifiers' muss eine Liste sein")
        for i, m in enumerate(mods):
            if not isinstance(m, dict):
                raise RiskRuleError(f"Regel {name!r} Modifier {i}: kein Mapping")
            when = m.get("when")
            if not isinstance(when, str) or when not in PREDICATES:
                raise RiskRuleError(
                    f"Regel {name!r} Modifier {i}: unbekannter when-Name {when!r}"
                )
            try:
                float(m.get("add"))
            except (TypeError, ValueError) as exc:
                raise RiskRuleError(
                    f"Regel {name!r} Modifier {i}: 'add' ist keine Zahl"
                ) from exc

    # ------------------------------------------------------------------ #
    # Bewerten
    # ------------------------------------------------------------------ #

    def evaluate(
        self,
        event: Event,
        context: RiskContext | None = None,
    ) -> RiskAssessment | None:
        """
        Bewertet ein Event.

        Sucht rules[event_type]; fehlt es, greift default.
        Rueckgabe ist immer ein RiskAssessment, ausser context ist
        unbrauchbar (sollte nicht vorkommen, da default Pflicht ist).
        """
        ctx = context or RiskContext(
            now=datetime.now(timezone.utc),
            network_id=event.network_id,
        )

        rule = self._rules.get(event.event_type) or self._default
        if not rule:
            # Kann durch Pflicht-default nicht passieren; defensiv.
            return None

        rule_id = str(rule.get("rule_id") or event.event_type or "default")
        base = float(rule["base"])

        modifiers: list[tuple[str, float]] = []
        reasons: list[str] = []

        for m in rule.get("modifiers", []):
            when = m["when"]
            fn = PREDICATES[when]
            try:
                hit = bool(fn(event, ctx))
            except Exception:  # noqa: BLE001 - Predicates werfen nie, aber fail safe
                hit = False
            if not hit:
                continue
            add = float(m["add"])
            modifiers.append((when, add))
            reason = m.get("reason")
            if isinstance(reason, str) and reason:
                reasons.append(reason)
            else:
                reasons.append(when)

        raw = base + sum(v for _n, v in modifiers)
        score = clamp_score(raw)
        category = score_to_category(score, self._thresholds)

        return RiskAssessment(
            event_id=event.event_id,
            rule_id=rule_id,
            score=score,
            category=category,
            base=base,
            modifiers=modifiers,
            reasons=reasons,
        )

    # ------------------------------------------------------------------ #
    # Introspection (fuer Tests / Debug)
    # ------------------------------------------------------------------ #

    @property
    def thresholds(self) -> dict[str, float]:
        return dict(self._thresholds)

    @property
    def known_event_types(self) -> set[str]:
        return set(self._rules.keys())

    def has_rule(self, event_type: str) -> bool:
        return event_type in self._rules


__all__ = [
    "PREDICATES",
    "RiskEngine",
]
