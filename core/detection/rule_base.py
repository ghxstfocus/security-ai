# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Basis-Interface fuer Detection-Regeln.

Eine Regel bekommt ein einzelnes Event plus einen RuleContext und
liefert 0..N neue Events zurueck. Regeln sind zustandslos; Zustand
(z.B. Zeitfenster fuer port_scan) liegt im RuleContext.state.

Verwendung:

    from core.detection.rule_base import Rule, RuleContext, RuleState

    class MyRule(Rule):
        id = "my_rule"
        event_types = frozenset({"device_presence"})
        severity = Severity.WARNING

        def evaluate(self, event, context):
            if event.data.get("known") is False:
                return [new_event(...)]
            return []
"""
from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from core.events.event import Event, Severity


class RuleError(Exception):
    """Basis-Fehler fuer Detection-Regeln."""


class RuleValidationError(RuleError):
    """Regel ist ungueltig (fehlende Attribute, falsche Typen)."""


class RuleState:
    """
    Thread-sicherer Ringpuffer pro Regel-Instanz.

    Speichert Werte unter einem Key (z.B. Quell-IP) und behaelt
    pro Key nur die letzten `maxlen` Eintraege.

    Verwendung:

        state.record("192.168.178.87", (now, 22))
        eintraege = state.get("192.168.178.87")
        state.clear()
    """

    def __init__(self, maxlen: int = 100) -> None:
        if maxlen <= 0:
            raise ValueError("maxlen muss > 0 sein")
        self._maxlen = maxlen
        self._lock = threading.Lock()
        self._store: dict[str, deque[Any]] = {}

    def record(self, key: str, value: Any) -> None:
        """Fuegt einen Wert unter `key` hinzu (aeltere Werte fallen raus)."""
        with self._lock:
            buf = self._store.get(key)
            if buf is None:
                buf = deque(maxlen=self._maxlen)
                self._store[key] = buf
            buf.append(value)

    def get(self, key: str) -> list[Any]:
        """Gibt eine Kopie der aktuellen Werte fuer `key` zurueck."""
        with self._lock:
            buf = self._store.get(key)
            return list(buf) if buf is not None else []

    def keys(self) -> list[str]:
        """Gibt alle bekannten Keys zurueck."""
        with self._lock:
            return list(self._store.keys())

    def clear(self) -> None:
        """Leert den gesamten Zustand (z.B. nach Neustart oder in Tests)."""
        with self._lock:
            self._store.clear()

    @property
    def maxlen(self) -> int:
        return self._maxlen


@dataclass
class RuleContext:
    """
    Kontext, den eine Regel bei evaluate() bekommt.

    - now:         aktueller Zeitstempel (UTC)
    - network_id:  Netzwerk, in dem das Event auftrat
    - config:      regel-spezifische Konfiguration aus detection/rules.yaml
    - state:       Ringpuffer pro Regel (thread-sicher)
    - history:     optionaler Zugriff auf vergangene Events
                   Signatur: history(event_type: str, limit: int) -> list[Event]
    - snapshot:    optionaler Inventory-Snapshot (Punkt 74):
                   {"devices": set, "whitelist": set,
                    "first_seen": {identifier: datetime}}
                   Fail-safe: None, wenn nicht uebergeben.
                   Regeln, die Snapshot brauchen, pruefen auf None.
    """
    now: datetime
    network_id: str
    config: dict[str, Any] = field(default_factory=dict)
    state: RuleState = field(default_factory=RuleState)
    history: Callable[[str, int], list[Event]] | None = None
    snapshot: dict[str, Any] | None = None

    def lookup(self, event_type: str, limit: int = 100) -> list[Event]:
        """
        Bequemer Zugriff auf die History.

        Gibt [] zurueck, wenn keine history-Funktion gesetzt ist.
        """
        if self.history is None:
            return []
        return self.history(event_type, limit)


class Rule(ABC):
    """
    Abstrakte Basisklasse fuer Detection-Regeln.

    Pflicht-Attribute:
        id:          eindeutiger Name der Regel (z.B. "unknown_device")
        event_types: Menge von Event-Typen, die diese Regel triggern
        severity:    Basis-Schweregrad fuer erzeugte Events

    Pflicht-Methode:
        evaluate(event, context) -> list[Event]

    Regeln sind zustandslos. Zustand gehoert in context.state.
    """

    id: str = ""
    event_types: frozenset[str] = frozenset()
    severity: Severity = Severity.INFO
    description: str = ""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Validierung erst, wenn die Klasse konkret ist (nicht ABC selbst).
        if getattr(cls, "__abstractmethods__", None):
            return
        cls._validate_class()

    @classmethod
    def _validate_class(cls) -> None:
        if not cls.id or not isinstance(cls.id, str):
            raise RuleValidationError(
                f"{cls.__name__}: id muss ein nicht-leerer String sein"
            )
        if not isinstance(cls.event_types, frozenset):
            raise RuleValidationError(
                f"{cls.__name__}: event_types muss ein frozenset sein"
            )
        if not cls.event_types:
            raise RuleValidationError(
                f"{cls.__name__}: event_types darf nicht leer sein"
            )
        if not isinstance(cls.severity, Severity):
            raise RuleValidationError(
                f"{cls.__name__}: severity muss ein Severity-Enum sein"
            )

    @abstractmethod
    def evaluate(self, event: Event, context: RuleContext) -> list[Event]:
        """
        Prueft ein Event und liefert 0..N neue Events zurueck.

        Regeln, die nicht triggern, geben [] zurueck.
        Die Regel entscheidet NICHT, ob ein Alarm gesendet wird,
        wie schwer er ist oder ob ein Mensch ihn sehen muss.
        """
        raise NotImplementedError

    def matches(self, event: Event) -> bool:
        """True, wenn event.event_type in event_types liegt."""
        return event.event_type in self.event_types

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{type(self).__name__} id={self.id!r}>"


__all__ = [
    "Rule",
    "RuleContext",
    "RuleError",
    "RuleState",
    "RuleValidationError",
]
