"""
Detection Engine — laedt Regeln und wendet sie auf Events an.

Verwendung:

    from core.detection.engine import DetectionEngine
    from core.detection.rule_base import RuleState

    engine = DetectionEngine()
    engine.load_rules_from_package("core.detection.rules")
    results = engine.process(event)

    for r in results:
        for alert in r.alerts:
            print(alert.to_json())

Die Engine ist zustandslos bis auf die Regel-Registry. Zustand
(z.B. Zeitfenster) liegt in den RuleStates, die die Engine pro
Regel-ID verwaltet und ueber den RuleContext weitergibt.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
from dataclasses import dataclass, field
from datetime import datetime, timezone, UTC
from typing import Any, Iterable

from core.detection.rule_base import (
    Rule,
    RuleContext,
    RuleError,
    RuleState,
)
from core.events.event import Event, new_event


class DetectionEngineError(Exception):
    """Basis-Fehler der Detection Engine."""


class RuleExecutionError(DetectionEngineError):
    """Eine Regel hat waehrend evaluate() eine Exception geworfen."""

    def __init__(self, rule_id: str, original: BaseException) -> None:
        super().__init__(f"Regel {rule_id!r} fehlgeschlagen: {original!r}")
        self.rule_id = rule_id
        self.original = original


@dataclass
class RuleRunReport:
    """
    Ergebnis der Ausfuehrung einer einzelnen Regel.

    - rule_id:  ID der Regel
    - alerts:   erzeugte Events (0..N)
    - error:    Exception, falls die Regel gecrasht ist (sonst None)
    - skipped:  True, wenn die Regel fuer dieses Event nicht zustaendig war
    """
    rule_id: str
    alerts: list[Event] = field(default_factory=list)
    error: RuleExecutionError | None = None
    skipped: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and not self.skipped


class DetectionEngine:
    """
    Registriert Regeln und wendet sie auf Events an.

    Thread-Sicherheit: register/get/list sind unkritisch nach dem
    Setup. process() ist read-only auf der Registry. Die RuleStates
    sind intern thread-sicher (siehe rule_base.RuleState).
    """

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}
        self._states: dict[str, RuleState] = {}

    # ------------------------------------------------------------------ #
    # Registry
    # ------------------------------------------------------------------ #

    def register(self, rule: Rule, state_maxlen: int = 100) -> None:
        """Registriert eine Regel-Instanz. Doppelte IDs sind ein Fehler."""
        if not isinstance(rule, Rule):
            raise DetectionEngineError(
                f"register erwartet eine Rule, bekam {type(rule).__name__}"
            )
        if rule.id in self._rules:
            raise DetectionEngineError(f"Regel-ID doppelt: {rule.id!r}")
        self._rules[rule.id] = rule
        self._states[rule.id] = RuleState(maxlen=state_maxlen)

    def get(self, rule_id: str) -> Rule:
        try:
            return self._rules[rule_id]
        except KeyError as exc:
            raise DetectionEngineError(f"Regel unbekannt: {rule_id!r}") from exc

    def list(self) -> list[Rule]:
        return list(self._rules.values())

    def state_for(self, rule_id: str) -> RuleState:
        """Gibt den RuleState einer Regel zurueck (z.B. fuer Tests)."""
        try:
            return self._states[rule_id]
        except KeyError as exc:
            raise DetectionEngineError(f"Regel unbekannt: {rule_id!r}") from exc

    def reset_states(self) -> None:
        """Leert alle RuleStates (z.B. nach Neustart oder in Tests)."""
        for st in self._states.values():
            st.clear()

    # ------------------------------------------------------------------ #
    # Laden aus Package
    # ------------------------------------------------------------------ #

    def load_rules_from_package(
        self,
        package_name: str,
        configs: dict[str, dict[str, Any]] | None = None,
    ) -> list[str]:  # type: ignore[valid-type]  # Methode list verdeckt Builtin
        """
        Laedt alle Regel-Klassen aus einem Package.

        Erwartet: package_name ist importierbar, enthaelt Module mit
        Rule-Subklassen. Jede konkrete Subklasse wird instanziiert
        (ohne Argumente) und registriert.

        configs: optionale dict rule_id -> config, wird pro Engine-Lauf
                 ueber den RuleContext bereitgestellt (nicht hier).

        Rueckgabe: Liste der geladenen Regel-IDs.
        """
        try:
            package = importlib.import_module(package_name)
        except ImportError as exc:
            raise DetectionEngineError(
                f"Package nicht importierbar: {package_name!r}"
            ) from exc

        loaded: list[str] = []
        for _finder, mod_name, _ispkg in pkgutil.iter_modules(package.__path__):
            full = f"{package_name}.{mod_name}"
            module = importlib.import_module(full)
            for _name, obj in inspect.getmembers(module, inspect.isclass):
                if obj is Rule or not issubclass(obj, Rule):
                    continue
                if inspect.isabstract(obj):
                    continue
                if obj.__module__ != full:
                    # Nicht in diesem Modul definiert (Import).
                    continue
                if obj.id in self._rules:
                    continue
                instance = obj()
                self.register(instance)
                loaded.append(instance.id)
        return loaded

    # ------------------------------------------------------------------ #
    # Verarbeitung
    # ------------------------------------------------------------------ #

    def process(
        self,
        event: Event,
        configs: dict[str, dict[str, Any]] | None = None,
        history: Any = None,
        now: datetime | None = None,
    ) -> list[RuleRunReport]:  # type: ignore[valid-type]  # Methode list verdeckt Builtin
        """
        Wendet alle zustaendigen Regeln auf ein Event an.

        - configs: dict rule_id -> config (aus detection/rules.yaml)
        - history: optionale Callable(event_type, limit) -> list[Event]
        - now:     Zeitstempel (Default: utcnow)

        Regeln, deren event_types das Event nicht enthalten, werden
        mit skipped=True uebersprungen. Regel-Fehler werden gefangen
        und im Report als error zurueckgegeben; andere Regeln laufen
        weiter.
        """
        configs = configs or {}
        now = now or datetime.now(UTC)
        reports: list[RuleRunReport] = []

        for rule in self._rules.values():
            if not rule.matches(event):
                reports.append(RuleRunReport(rule_id=rule.id, skipped=True))
                continue

            ctx = RuleContext(
                now=now,
                network_id=event.network_id,
                config=dict(configs.get(rule.id, {})),
                state=self._states[rule.id],
                history=history,
            )
            try:
                alerts = rule.evaluate(event, ctx)
            except RuleError as exc:
                reports.append(
                    RuleRunReport(
                        rule_id=rule.id,
                        error=RuleExecutionError(rule.id, exc),
                    )
                )
                continue
            except Exception as exc:  # noqa: BLE001
                reports.append(
                    RuleRunReport(
                        rule_id=rule.id,
                        error=RuleExecutionError(rule.id, exc),
                    )
                )
                continue

            if not isinstance(alerts, list):
                reports.append(
                    RuleRunReport(
                        rule_id=rule.id,
                        error=RuleExecutionError(
                            rule.id,
                            TypeError(
                                f"evaluate() muss list[Event] liefern, "
                                f"bekam {type(alerts).__name__}"
                            ),
                        ),
                    )
                )
                continue

            for a in alerts:
                if not isinstance(a, Event):
                    reports.append(
                        RuleRunReport(
                            rule_id=rule.id,
                            error=RuleExecutionError(
                                rule.id,
                                TypeError(
                                    "evaluate() lieferte ein Nicht-Event: "
                                    f"{type(a).__name__}"
                                ),
                            ),
                        )
                    )
                    break
            else:
                reports.append(RuleRunReport(rule_id=rule.id, alerts=alerts))

        return reports

    def alerts_from(self, reports: Iterable[RuleRunReport]) -> list[Event]:  # type: ignore[valid-type]  # Methode list verdeckt Builtin
        """Sammelt alle Alerts aus mehreren Reports flach ein."""
        out: list[Event] = []
        for r in reports:
            out.extend(r.alerts)
        return out

    def errors_from(self, reports: Iterable[RuleRunReport]) -> list[RuleExecutionError]:  # type: ignore[valid-type]  # Methode list verdeckt Builtin
        """Sammelt alle Fehler aus mehreren Reports."""
        return [r.error for r in reports if r.error is not None]


__all__ = [
    "DetectionEngine",
    "DetectionEngineError",
    "RuleExecutionError",
    "RuleRunReport",
]
