"""
Orchestrator der Security AI.

Klebt Inventory, Detection und Risk zusammen:

    process(event):
      1) Inventory-Update (nur bei device_presence/device_offline)
      2) DetectionEngine.process()
      3) RiskEngine.evaluate() fuer jeden Alert
      4) Audit (Phase 3, hier nur vorbereitet)
      5) ProcessingResult zurueck

Deterministisch: DB wird ausschliesslich hier angefasst.
Detection und Risk bekommen nur Snapshots.

Fail-safe: bei DB-Fehler wird ein leeres Inventory verwendet.
is_in_inventory wird dann False -> Risiko-Score geht eher hoch.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.detection.engine import DetectionEngine, RuleRunReport
from core.events.event import Event, EventType, with_data
from core.inventory.repository import (
    DEFAULT_DB_PATH,
    DEFAULT_MIGRATIONS_DIR,
    DeviceRepository,
    apply_migrations,
    connect,
)
from core.inventory.whitelist import WhitelistRepository
from core.risk.engine import RiskEngine
from core.risk.models import RiskAssessment, RiskContext

try:
    import yaml  # PyYAML
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "PyYAML wird gebraucht. Installieren mit: apt install python3-yaml"
    ) from exc


DEFAULT_RULES_DIR = "core/detection/rules"
DEFAULT_RULES_PACKAGE = "core.detection.rules"
DEFAULT_DETECTION_CONFIG = "detection/rules.yaml"
DEFAULT_RISK_RULES = "core/risk/rules.yaml"

# Event-Typen, die das Inventory aktualisieren.
_INVENTORY_EVENTS = frozenset({
    EventType.DEVICE_PRESENCE.value,
    EventType.DEVICE_OFFLINE.value,
})


@dataclass(frozen=True)
class ProcessingResult:
    """
    Ergebnis der Verarbeitung eines Events.

    - event:       Eingangs-Event
    - reports:     alle RuleRunReports (inkl. skipped / errors)
    - alerts:      flach eingesammelte Detection-Alerts
    - assessments: ein RiskAssessment pro Alert
    """
    event: Event
    reports: list[RuleRunReport] = field(default_factory=list)
    alerts: list[Event] = field(default_factory=list)
    assessments: list[RiskAssessment] = field(default_factory=list)

    @property
    def has_alerts(self) -> bool:
        return bool(self.alerts)

    @property
    def max_score(self) -> float:
        if not self.assessments:
            return 0.0
        return max(a.score for a in self.assessments)


class SecurityAI:
    """
    Orchestrator.

    - db_path:               SQLite-Datei fuer Inventory
    - migrations_dir:        Verzeichnis mit data/migrations/*.sql
    - detection_config_path: YAML mit Detection-Configs
    - risk_rules_path:       YAML mit Risk-Regeln
    - rules_package:         Python-Package mit Detection-Regeln
    """

    def __init__(
        self,
        db_path: Path | str = DEFAULT_DB_PATH,
        migrations_dir: Path | str = DEFAULT_MIGRATIONS_DIR,
        detection_config_path: Path | str = DEFAULT_DETECTION_CONFIG,
        risk_rules_path: Path | str = DEFAULT_RISK_RULES,
        rules_package: str = DEFAULT_RULES_PACKAGE,
    ) -> None:
        self._conn = connect(db_path)
        apply_migrations(self._conn, migrations_dir)

        self._devices = DeviceRepository(self._conn)
        self._whitelist = WhitelistRepository(self._conn)

        self._detection = DetectionEngine()
        self._detection.load_rules_from_package(rules_package)

        self._risk = RiskEngine(risk_rules_path)

        self._detection_config_path = Path(detection_config_path)
        self._detection_config = self._load_detection_config(
            self._detection_config_path
        )

    # ------------------------------------------------------------------ #
    # Setup / Config
    # ------------------------------------------------------------------ #

    @staticmethod
    def _load_detection_config(path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return data if isinstance(data, dict) else {}

    # ------------------------------------------------------------------ #
    # Inventory-Snapshot
    # ------------------------------------------------------------------ #

    def _load_inventory_snapshot(self) -> dict[str, Any]:
        """
        Baut {"devices": set, "whitelist": set, "first_seen": dict}.

        Fail-safe: bei DB-Fehler -> leeres Dict. is_in_inventory/whitelist
        werden dann False, der Score geht eher hoch.
        """
        try:
            devices = self._devices.list_all()
            identifiers = {d.identifier for d in devices}
            first_seen = {d.identifier: d.first_seen for d in devices}
            whitelist = self._whitelist.identifiers()
        except Exception:  # noqa: BLE001 - fail-safe
            return {"devices": set(), "whitelist": set(), "first_seen": {}}
        return {
            "devices": identifiers,
            "whitelist": whitelist,
            "first_seen": first_seen,
        }

    # ------------------------------------------------------------------ #
    # Inventory-Update (nur device_presence / device_offline)
    # ------------------------------------------------------------------ #

    def _update_inventory(self, event: Event) -> None:
        if event.event_type not in _INVENTORY_EVENTS:
            return

        identifier = event.data.get("identifier")
        if not identifier or not isinstance(identifier, str):
            return

        if event.event_type == EventType.DEVICE_PRESENCE.value:
            self._devices.upsert_seen(
                identifier,
                entity_name=event.data.get("entity_name"),
                network_type=event.data.get("network_type"),
                event_type="device_seen",
                data={
                    "trigger_event_id": event.event_id,
                    "known": event.data.get("known"),
                },
                timestamp=event.timestamp,
            )
        elif event.event_type == EventType.DEVICE_OFFLINE.value:
            # mark_offline aktualisiert last_seen NICHT.
            # Falls das Geraet noch nicht existiert, legen wir es an,
            # damit die History nicht ins Leere greift.
            if self._devices.get(identifier) is None:
                self._devices.upsert_seen(
                    identifier,
                    entity_name=event.data.get("entity_name"),
                    network_type=event.data.get("network_type"),
                    event_type="device_seen",
                    data={"trigger_event_id": event.event_id},
                    timestamp=event.timestamp,
                )
            self._devices.mark_offline(
                identifier,
                data={"trigger_event_id": event.event_id},
                timestamp=event.timestamp,
            )

    # ------------------------------------------------------------------ #
    # Verarbeitung
    # ------------------------------------------------------------------ #

    def process(self, event: Event) -> ProcessingResult:
        """
        Verarbeitet ein Event durch den ganzen Stack.

        Reihenfolge: Inventory-Update -> Detection -> Risk.
        """
        # 0) Pre-Snapshot (Zustand VOR dem Update).
        #    Wird gebraucht, um "first_seen" fuer Alerts zu setzen.
        pre_snapshot = self._load_inventory_snapshot()

        # 1) Inventory-Update
        try:
            self._update_inventory(event)
        except Exception:  # noqa: BLE001 - Detection/Risk sollen trotzdem laufen
            # Fail-safe: wir loggen (noch) nicht, aber wir brechen nicht ab.
            pass

        # 2) Detection
        reports = self._detection.process(
            event,
            configs=self._detection_config,
            now=event.timestamp,
        )
        alerts = self._detection.alerts_from(reports)

        # 2b) Alerts anreichern: first_seen setzen, wenn der
        #     Identifier vor dem Inventory-Update NICHT drin war.
        #     Alerts sind frozen; with_data erzeugt neue Events.
        devices_before = pre_snapshot.get("devices", set())
        enriched_alerts: list[Event] = []
        for alert in alerts:
            ident = alert.data.get("identifier")
            if ident:
                alert = with_data(
                    alert, {"first_seen": ident not in devices_before}
                )
            enriched_alerts.append(alert)
        alerts = enriched_alerts

        # 3) Risk pro Alert
        snapshot = self._load_inventory_snapshot()
        ctx = RiskContext(
            now=event.timestamp,
            network_id=event.network_id,
            inventory=snapshot,
        )
        assessments: list[RiskAssessment] = []
        for alert in alerts:
            a = self._risk.evaluate(alert, ctx)
            if a is not None:
                assessments.append(a)

        # 4) Audit (Phase 3)
        # 5) Ergebnis
        return ProcessingResult(
            event=event,
            reports=reports,
            alerts=alerts,
            assessments=assessments,
        )

    def process_many(self, events: list[Event]) -> list[ProcessingResult]:
        return [self.process(e) for e in events]

    # ------------------------------------------------------------------ #
    # Read-only Zugriff (fuer Tests / Debug)
    # ------------------------------------------------------------------ #

    @property
    def devices(self) -> DeviceRepository:
        return self._devices

    @property
    def whitelist(self) -> WhitelistRepository:
        return self._whitelist

    @property
    def detection(self) -> DetectionEngine:
        return self._detection

    @property
    def risk(self) -> RiskEngine:
        return self._risk

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001
            pass


__all__ = [
    "DEFAULT_DETECTION_CONFIG",
    "DEFAULT_RISK_RULES",
    "DEFAULT_RULES_PACKAGE",
    "ProcessingResult",
    "SecurityAI",
]
