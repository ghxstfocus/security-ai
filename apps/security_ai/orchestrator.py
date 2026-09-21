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

import hashlib
import json

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
from harness.agent_loop.loop import (
    AgentLoop,
    LoopBudget,
    LoopResult,
)
from harness.audit.writer import (
    AuditEntry,
    AuditWriter,
    AuditWriteError,
)
from harness.policy_engine.engine import PolicyEngine
from harness.policy_engine.policy import PolicyContext
from harness.tool_registry.registry import ToolRegistry
from tools.get_devices import GET_DEVICES_TOOL
from tools.nmap_scan import NMAP_SCAN_TOOL
from tools.read_logs import READ_LOGS_TOOL
from tools.telegram_alert import TELEGRAM_ALERT_TOOL
from tools.whitelist_check import WHITELIST_CHECK_TOOL

try:
    import yaml  # PyYAML
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "PyYAML wird gebraucht. Installieren mit: apt install python3-yaml"
    ) from exc


from apps.security_ai.planning import SecurityPlanModel

DEFAULT_RULES_DIR = "core/detection/rules"
DEFAULT_RULES_PACKAGE = "core.detection.rules"
DEFAULT_DETECTION_CONFIG = "detection/rules.yaml"
DEFAULT_RISK_RULES = "core/risk/rules.yaml"
DEFAULT_POLICY_RULES = "policies/tools.yaml"

# Erlaubte Netzwerke fuer die Policy Engine (nmap etc.)
DEFAULT_APP_CONFIG = "apps/security_ai/config.yaml"

DEFAULT_LOOP_TRIGGER_CATEGORIES = frozenset({
    "SECURITY_ALERT",
    "CONFIRMED",
})

DEFAULT_AUTHORIZED_NETWORKS = frozenset({
    "192.168.178.0/24",
    "192.168.189.0/24",
    "127.0.0.1/32",
})

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
    loop_results: list[LoopResult] = field(default_factory=list)

    @property
    def has_alerts(self) -> bool:
        return bool(self.alerts)

    @property
    def max_score(self) -> float:
        if not self.assessments:
            return 0.0
        return max(a.score for a in self.assessments)


def _build_default_registry() -> ToolRegistry:
    """Baut die Standard-ToolRegistry mit den 5 Tools."""
    reg = ToolRegistry()
    reg.register(NMAP_SCAN_TOOL)
    reg.register(READ_LOGS_TOOL)
    reg.register(GET_DEVICES_TOOL)
    reg.register(WHITELIST_CHECK_TOOL)
    reg.register(TELEGRAM_ALERT_TOOL)
    return reg


class ProcessingAuditError(Exception):
    """Ein oder mehrere Audit-Eintraege konnten nicht geschrieben werden."""

    def __init__(self, errors: list[Exception]) -> None:
        msg = f"{len(errors)} Audit-Fehler beim Verarbeiten"
        super().__init__(msg)
        self.errors = list(errors)


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
        audit_base_dir: Path | str = "audit-logs",
        audit_writer: AuditWriter | None = None,
        tool_registry: ToolRegistry | None = None,
        policy_engine: PolicyEngine | None = None,
        loop_budget: LoopBudget | None = None,
        authorized_networks: frozenset[str] | None = None,
        app_config_path: Path | str = DEFAULT_APP_CONFIG,
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

        self._audit = audit_writer or AuditWriter(base_dir=audit_base_dir)
        self._audit_base_dir = Path(audit_base_dir)
        self._inventory_version_cache: str | None = None

        # Tools + Policy
        self._tool_registry = tool_registry or _build_default_registry()
        self._policy_engine = policy_engine or PolicyEngine(
            DEFAULT_POLICY_RULES
        )
        self._authorized_networks = (
            authorized_networks
            if authorized_networks is not None
            else DEFAULT_AUTHORIZED_NETWORKS
        )
        self._loop_budget = loop_budget or LoopBudget()

        self._app_config_path = Path(app_config_path)
        self._app_config = self._load_app_config(self._app_config_path)
        cats = self._app_config.get("loop_trigger_categories")
        if isinstance(cats, list) and all(isinstance(c, str) for c in cats):
            self._loop_trigger_categories = frozenset(cats)
        else:
            self._loop_trigger_categories = DEFAULT_LOOP_TRIGGER_CATEGORIES

        # AgentLoop: stateless, bekommt policy_context pro run()
        self._loop = AgentLoop(
            registry=self._tool_registry,
            audit=self._audit,
            model=SecurityPlanModel(),
            budget=self._loop_budget,
            network_id="homelab-default",
            policy_engine=self._policy_engine,
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

    @staticmethod
    def _load_app_config(path: Path) -> dict[str, Any]:
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

    def _update_inventory(self, event: Event) -> bool:
        if event.event_type not in _INVENTORY_EVENTS:
            return False

        identifier = event.data.get("identifier")
        if not identifier or not isinstance(identifier, str):
            return False

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

        return True

    # ------------------------------------------------------------------ #
    # Audit-Helper
    # ------------------------------------------------------------------ #

    @staticmethod
    def _inventory_hash(snapshot: dict[str, Any]) -> str:
        """SHA256 ueber sortierte Identifier-Mengen (devices + whitelist)."""
        payload = {
            "devices": sorted(snapshot.get("devices", set()) or set()),
            "whitelist": sorted(snapshot.get("whitelist", set()) or set()),
        }
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _inventory_version(self) -> str:
        """Hoechste schema_migrations-Version als String, z.B. "0002". "0000" wenn leer."""
        if self._inventory_version_cache is not None:
            return self._inventory_version_cache
        try:
            row = self._conn.execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()
            v = row[0] if row and row[0] is not None else 0
            self._inventory_version_cache = f"{int(v):04d}"
        except Exception:  # noqa: BLE001
            self._inventory_version_cache = "0000"
        return self._inventory_version_cache

    # ------------------------------------------------------------------ #
    # Policy-Context
    # ------------------------------------------------------------------ #

    def _build_policy_context(self, event: Event) -> PolicyContext:
        """
        Baut pro Event einen frischen PolicyContext.

        now = event.timestamp, nicht datetime.now(), damit die
        Policy-Entscheidung deterministisch und replay-faehig ist.
        """
        return PolicyContext(
            network_id=event.network_id,
            authorized_networks=self._authorized_networks,
            now=event.timestamp,
            config={},
        )

    # ------------------------------------------------------------------ #
    # Verarbeitung
    # ------------------------------------------------------------------ #

    def process(self, event: Event) -> ProcessingResult:
        """
        Verarbeitet ein Event durch den ganzen Stack.

        Reihenfolge: Pre-Snapshot -> Inventory-Update -> Detection
        -> Alerts anreichern -> Risk -> Audit.

        Audit-Fehler werden gesammelt; am Ende wird
        ProcessingAuditError geworfen, ProcessingResult nicht
        zurueckgegeben. Fail closed.
        """
        audit_errors: list[Exception] = []
        audit_entries: list[AuditEntry] = []

        def _audit(
            tool: str,
            details: dict[str, Any],
            execution_status: str = "OK",
        ) -> None:
            try:
                entry = self._audit.log(
                    agent="security_ai",
                    tool=tool,
                    policy_result="ALLOWED",
                    permission_level=0,
                    execution_status=execution_status,
                    details=details,
                    network_id=event.network_id,
                )
                audit_entries.append(entry)
            except Exception as exc:  # noqa: BLE001
                audit_errors.append(exc)

        # 0) Pre-Snapshot
        pre_snapshot = self._load_inventory_snapshot()

        # 1) Inventory-Update
        updated = False
        try:
            updated = self._update_inventory(event)
        except Exception:  # noqa: BLE001 - Detection/Risk laufen weiter
            pass

        if updated:
            identifier = event.data.get("identifier")
            action = (
                "mark_offline"
                if event.event_type == EventType.DEVICE_OFFLINE.value
                else "upsert_seen"
            )
            _audit(
                tool="inventory_repository",
                details={
                    "kind": "inventory_update",
                    "action": action,
                    "identifier": identifier,
                    "event_id": event.event_id,
                },
            )

        # 2) Detection
        reports = self._detection.process(
            event,
            configs=self._detection_config,
            now=event.timestamp,
        )
        for r in reports:
            if r.skipped:
                continue
            _audit(
                tool="detection_engine",
                details={
                    "kind": "detection_result",
                    "rule_id": r.rule_id,
                    "alert_count": len(r.alerts),
                    "error": str(r.error) if r.error else None,
                    "event_id": event.event_id,
                },
                execution_status="ERROR" if r.error else "OK",
            )

        alerts = self._detection.alerts_from(reports)

        # 2b) Alerts anreichern: first_seen
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
            if a is None:
                continue
            assessments.append(a)
            _audit(
                tool="risk_engine",
                details={
                    "kind": "risk_assessment",
                    "event_id": a.event_id,
                    "rule_id": a.rule_id,
                    "score": a.score,
                    "category": a.category.value,
                    "base": a.base,
                    "modifiers": [list(m) for m in a.modifiers],
                    "reasons": list(a.reasons),
                },
            )

        # 3b) Agent Loop fuer Alerts mit hoher Risk-Category
        loop_results: list[LoopResult] = []
        for alert, assessment in zip(alerts, assessments):
            if assessment.category.value not in self._loop_trigger_categories:
                continue
            enriched = with_data(alert, {
                "risk_category": assessment.category.value,
                "risk_score": assessment.score,
            })
            policy_ctx = self._build_policy_context(enriched)
            loop_result = self._loop.run(
                enriched, policy_context=policy_ctx,
            )
            loop_results.append(loop_result)
            _audit(
                tool="agent_loop",
                details={
                    "kind": "loop_result",
                    "loop_status": loop_result.status,
                    "step_count": len(loop_result.steps),
                    "successful_steps": sum(
                        1 for s in loop_result.steps if s.status == "OK"
                    ),
                    "error_steps": sum(
                        1 for s in loop_result.steps if s.status == "ERROR"
                    ),
                    "alert_event_id": alert.event_id,
                    "assessment_score": assessment.score,
                    "assessment_category": assessment.category.value,
                },
                execution_status=loop_result.status,
            )

        # 4) Snapshot-Hash
        _audit(
            tool="orchestrator",
            details={
                "kind": "snapshot",
                "inventory_hash": self._inventory_hash(snapshot),
                "inventory_version": self._inventory_version(),
                "event_id": event.event_id,
            },
        )

        # 5) Audit-Fehler?
        if audit_errors:
            raise ProcessingAuditError(audit_errors)

        return ProcessingResult(
            event=event,
            reports=reports,
            alerts=alerts,
            assessments=assessments,
            loop_results=loop_results,
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
