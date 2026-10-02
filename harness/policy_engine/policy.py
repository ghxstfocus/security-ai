# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Datenmodelle der Policy Engine.

- Decision:        ALLOWED / APPROVAL_REQUIRED / FORBIDDEN
- PredicateResult: Ergebnis eines einzelnen Pruefers
                   (passed, on_fail, reason)
- PolicyDecision:  Ergebnis einer Policy-Auswertung
                   (decision, reason, matched_rule,
                    failed_predicates, tool_name, level)

Fail-closed-Prinzip: unklare Faelle werden zur strengsten
Entscheidung. Reihenfolge: FORBIDDEN > APPROVAL_REQUIRED > ALLOWED.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PolicyError(Exception):
    """Fehler in einer Policy (unbekannter Pruefer, ungueltige Config)."""


class Decision(str, Enum):
    """
    Ergebnis einer Policy-Auswertung.

    Reihenfolge fuer "strengste gewinnt":
        FORBIDDEN > APPROVAL_REQUIRED > ALLOWED
    """
    ALLOWED = "ALLOWED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    FORBIDDEN = "FORBIDDEN"

    def __str__(self) -> str:  # pragma: no cover
        return self.value

    @property
    def severity(self) -> int:
        """Zahl zum Vergleich (hoeher = strenger)."""
        return _SEVERITY[self]


_SEVERITY: dict[Decision, int] = {
    Decision.ALLOWED: 0,
    Decision.APPROVAL_REQUIRED: 1,
    Decision.FORBIDDEN: 2,
}


def strictest(a: Decision, b: Decision) -> Decision:
    """Gibt die strengere der beiden Entscheidungen zurueck."""
    return a if a.severity >= b.severity else b


@dataclass(frozen=True)
class PredicateResult:
    """
    Ergebnis eines einzelnen Pruefers.

    - passed:  True wenn der Pruefer erfuellt ist
    - on_fail: Decision, die bei passed=False ausgeloest wird
               (APPROVAL_REQUIRED fuer weiche, FORBIDDEN fuer
                harte Pruefer)
    - reason:  Klartext-Begruendung, landet im Audit
    """
    passed: bool
    on_fail: Decision = Decision.APPROVAL_REQUIRED
    reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.on_fail, Decision):
            raise PolicyError(
                f"on_fail muss ein Decision sein, nicht {type(self.on_fail).__name__}"
            )
        if self.on_fail is Decision.ALLOWED:
            raise PolicyError("on_fail darf nicht ALLOWED sein")


@dataclass(frozen=True)
class PolicyDecision:
    """
    Ergebnis der Policy-Auswertung fuer einen Tool-Aufruf.

    - decision:          finale Entscheidung
    - reason:            zusammengefasste Begruendung aus allen
                         Fehlern (leer bei ALLOWED)
    - matched_rule:      Name der Regel in policies/*.yaml, die
                         gegriffen hat (Tool-Name), oder None
    - failed_predicates: Namen der gescheiterten Pruefer
    - tool_name:         angefragtes Tool
    - level:             Permission-Level des Tools (0-5)
    """
    decision: Decision
    reason: str
    matched_rule: str | None
    failed_predicates: list[str] = field(default_factory=list)
    tool_name: str = ""
    level: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.decision, Decision):
            raise PolicyError(
                f"decision muss ein Decision sein, nicht {type(self.decision).__name__}"
            )
        if self.level < 0 or self.level > 5:
            raise PolicyError(f"level muss zwischen 0 und 5 liegen: {self.level}")

    @property
    def is_allowed(self) -> bool:
        return self.decision is Decision.ALLOWED

    @property
    def is_forbidden(self) -> bool:
        return self.decision is Decision.FORBIDDEN

    @property
    def needs_approval(self) -> bool:
        return self.decision is Decision.APPROVAL_REQUIRED

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "matched_rule": self.matched_rule,
            "failed_predicates": list(self.failed_predicates),
            "tool_name": self.tool_name,
            "level": self.level,
        }


@dataclass(frozen=True)
class PolicyContext:
    """
    Kontext fuer die Policy-Auswertung.

    - network_id:           Netzwerk, in dem der Aufruf stattfindet
    - authorized_networks:  erlaubte Ziele (IPs, Hostnames, CIDRs)
    - now:                  aktueller Zeitstempel (UTC)
    - config:               freie Konfiguration (z.B. read_only_paths)
    """
    network_id: str = "homelab-default"
    authorized_networks: frozenset[str] = field(default_factory=frozenset)
    now: Any = None
    config: dict[str, Any] = field(default_factory=dict)

    def has_network(self, target: str) -> bool:
        return target in self.authorized_networks


# Praktische Fabriken fuer den haeufigsten Fall
def allowed(tool_name: str, level: int = 0,
            matched_rule: str | None = None,
            reason: str = "alle Bedingungen erfuellt") -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.ALLOWED,
        reason=reason,
        matched_rule=matched_rule,
        failed_predicates=[],
        tool_name=tool_name,
        level=level,
    )


def forbidden(tool_name: str, reason: str, level: int = 0,
              matched_rule: str | None = None,
              failed: list[str] | None = None) -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.FORBIDDEN,
        reason=reason,
        matched_rule=matched_rule,
        failed_predicates=list(failed or []),
        tool_name=tool_name,
        level=level,
    )


def approval(tool_name: str, reason: str, level: int = 0,
             matched_rule: str | None = None,
             failed: list[str] | None = None) -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.APPROVAL_REQUIRED,
        reason=reason,
        matched_rule=matched_rule,
        failed_predicates=list(failed or []),
        tool_name=tool_name,
        level=level,
    )


__all__ = [
    "Decision",
    "PolicyContext",
    "PolicyDecision",
    "PolicyError",
    "PredicateResult",
    "allowed",
    "approval",
    "forbidden",
    "strictest",
]
