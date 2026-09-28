"""
Event-Modell — einheitliches Schema für alle Sicherheitsereignisse.

Events sind unveränderlich. Sie werden erzeugt, geloggt und niemals
überschrieben.

Verwendung:

    from core.events.event import Event, Severity, new_event_id

    event = Event(
        event_id=new_event_id(),
        timestamp=datetime.now(timezone.utc),
        source="fritzbox",
        event_type="device_presence",
        severity=Severity.WARNING,
        data={"identifier": "192.168.178.87", "known": False},
        network_id="homelab-ct101",
    )
"""
from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Schweregrad eines Events."""
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"

    def __str__(self) -> str:  # pragma: no cover
        return self.value


class EventType(str, Enum):
    """Bekannte Event-Typen. Erweiterbar durch neue Werte."""
    # Geräte
    DEVICE_PRESENCE = "device_presence"
    DEVICE_OFFLINE = "device_offline"
    UNKNOWN_DEVICE = "unknown_device"

    # Netzwerk
    PORT_SCAN = "port_scan"
    CONNECTION_ATTEMPT = "connection_attempt"
    SYN_PACKET = "syn_packet"
    HTTP_RECON = "http_recon"

    # Infrastruktur
    DOCKER_STATUS = "docker_status"
    PROXMOX_STATUS = "proxmox_status"

    # System
    SERVICE_STARTED = "service_started"
    SERVICE_STOPPED = "service_stopped"
    ERROR = "error"

    def __str__(self) -> str:  # pragma: no cover
        return self.value


@dataclass(frozen=True)
class Event:
    """
    Ein Sicherheitsereignis.

    Unveränderlich (frozen=True). Jede Änderung erzeugt ein neues Event.
    """
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: Severity
    data: dict[str, Any] = field(default_factory=dict)
    network_id: str = "homelab-default"

    def to_dict(self) -> dict[str, Any]:
        """Konvertiert Event zu einem serialisierbaren Dict."""
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["severity"] = self.severity.value
        return d

    def to_json(self) -> str:
        """Serialisiert Event als JSON-String."""
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Event:
        """Erzeugt Event aus Dict (Umkehrung von to_dict)."""
        return cls(
            event_id=d["event_id"],
            timestamp=datetime.fromisoformat(d["timestamp"]),
            source=d["source"],
            event_type=d["event_type"],
            severity=Severity(d["severity"]),
            data=d.get("data", {}),
            network_id=d.get("network_id", "homelab-default"),
        )


def new_event_id() -> str:
    """
    Erzeugt eine eindeutige Event-ID.

    Format: EVT-YYYY-MM-DD-XXXXXXXX
    Die letzten 8 Zeichen sind ein zufälliger Hex-String.
    """
    now = datetime.now(UTC)
    suffix = uuid.uuid4().hex[:8]
    return f"EVT-{now.strftime('%Y-%m-%d')}-{suffix}"


def new_event(
    source: str,
    event_type: str,
    severity: Severity,
    data: dict[str, Any] | None = None,
    network_id: str = "homelab-default",
) -> Event:
    """
    Bequemer Konstruktor mit automatischer ID und Zeitstempel.

    Verwendung:
        event = new_event("fritzbox", "device_presence", Severity.INFO,
                          {"identifier": "192.168.178.87"})
    """
    return Event(
        event_id=new_event_id(),
        timestamp=datetime.now(UTC),
        source=source,
        event_type=event_type,
        severity=severity,
        data=data or {},
        network_id=network_id,
    )


def with_data(event: Event, updates: dict[str, Any]) -> Event:
    """
    Neues Event mit gleichem event_id/timestamp, data um updates erweitert.

    Event bleibt frozen. Diese Funktion erzeugt eine neue Instanz.
    Bestehende Keys in event.data werden ueberschrieben.
    """
    new_data = dict(event.data)
    new_data.update(updates)
    return replace(event, data=new_data)


__all__ = [
    "Event",
    "EventType",
    "Severity",
    "new_event",
    "new_event_id",
    "with_data",
]
