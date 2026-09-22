"""
Inventory-Snapshot.

Reine Aggregation aus Device-Liste + Whitelist-Set.
Kein DB-Zugriff. Der Aufrufer (Orchestrator oder CLI) laedt
die Devices aus der DB und uebergibt sie hier.

Felder:
    device_count      Anzahl Devices
    whitelist_count   Anzahl Whitelist-Eintraege
    devices_online    Devices mit last_seen in recent_hours
    devices_offline   Devices mit last_seen aelter als offline_hours
    recently_added    identifiers, first_seen in recent_hours
    recently_offline  identifiers, last_seen aelter als offline_hours
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable


class InventorySnapshotError(RuntimeError):
    """Fehler beim Bau des Snapshots."""


def _get(obj: Any, *names: str) -> Any:
    """Liest das erste vorhandene Attribut oder Dict-Key."""
    for n in names:
        if isinstance(obj, dict) and n in obj:
            return obj[n]
        if hasattr(obj, n):
            return getattr(obj, n)
    return None


def _parse_ts(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return None
        return value
    if isinstance(value, str) and value:
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return None
        if dt.tzinfo is None:
            return None
        return dt
    return None


def build_inventory_snapshot(
    devices: Iterable[Any],
    whitelist_ids: Iterable[str],
    *,
    recent_hours: int = 24,
    offline_hours: int = 24,
    now: datetime | None = None,
) -> dict[str, Any]:
    """
    Baut einen Inventory-Snapshot.

    devices:         iterable von Device-Objekten oder dicts
                     mit identifier, last_seen, first_seen
    whitelist_ids:   iterable von identifiers in der Whitelist

    Fail-soft: Objekte ohne identifier werden uebersprungen.
    """
    if recent_hours < 0:
        raise InventorySnapshotError(
            "recent_hours muss >= 0 sein"
        )
    if offline_hours < 0:
        raise InventorySnapshotError(
            "offline_hours muss >= 0 sein"
        )

    now_dt = now or datetime.now(timezone.utc)
    recent_cut = now_dt - timedelta(hours=recent_hours)
    offline_cut = now_dt - timedelta(hours=offline_hours)

    device_count = 0
    devices_online = 0
    devices_offline = 0
    recently_added: list[str] = []
    recently_offline: list[str] = []

    for d in devices:
        ident = _get(d, "identifier")
        if not isinstance(ident, str) or not ident:
            continue
        device_count += 1

        first_seen = _parse_ts(_get(d, "first_seen"))
        last_seen = _parse_ts(_get(d, "last_seen"))

        if last_seen is not None:
            if last_seen >= recent_cut:
                devices_online += 1
            elif last_seen < offline_cut:
                devices_offline += 1
                recently_offline.append(ident)

        if first_seen is not None and first_seen >= recent_cut:
            recently_added.append(ident)

    wl_set = {x for x in whitelist_ids if isinstance(x, str) and x}

    return {
        "device_count": device_count,
        "whitelist_count": len(wl_set),
        "devices_online": devices_online,
        "devices_offline": devices_offline,
        "recently_added": sorted(set(recently_added)),
        "recently_offline": sorted(set(recently_offline)),
    }


__all__ = [
    "build_inventory_snapshot",
    "InventorySnapshotError",
]
