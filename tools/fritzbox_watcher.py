"""
Fritz!Box-Watcher: Producer fuer device_presence/device_offline.

Liest die Host-Liste der Fritz!Box via TR-064, vergleicht sie
mit dem letzten Lauf und schreibt Events als JSONL.

Eingang:
    Fritz!Box TR-064 (fritzconnection.FritzHosts.get_hosts_info).

Ausgang:
    data/events-YYYY-MM-DD.jsonl (UTC-Datum), append-only,
    eine JSON-Zeile pro Event (Event.to_json()).
    data/fritzbox_state.json (letzter Host-Zustand).

Lauf-Modell:
    systemd-Timer, OnUnitActiveSec=60s, OnBootSec=30s.
    Kein Dauerprozess.

Fail closed:
    Exit 0: Erfolg (auch bei 0 Events).
    Exit 1: Fritz!Box nicht erreichbar.
    Exit 2: Credentials fehlen.
    Exit 3: Schreibfehler (State oder Event-Datei).

identifier=MAC (stabil ueber DHCP).
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fritzconnection import FritzConnection
from fritzconnection.lib.fritzhosts import FritzHosts

# --- Fallback-Erkennung fuer Fritz!Box-Namen (Punkt 67a).
# Zwei Muster:
#   MAC-Format: PC-XX-XX-XX-XX-XX-XX (Bindestriche).
#   IP-Format:  PC-N-N-N-N (Bindestriche).
_FALLBACK_RE_MAC = re.compile(r"^PC-([0-9A-F]{2}-){5}[0-9A-F]{2}$")
_FALLBACK_RE_IP = re.compile(r"^PC-(\d{1,3}-){3}\d{1,3}$")
_FALLBACK_SENTINEL = "__FALLBACK__"


def _is_fallback_name(name: str) -> bool:
    """True, wenn der Fritz!Box-Name ein Fallback ist (Punkt 67a)."""
    if not name:
        return False
    return bool(
        _FALLBACK_RE_MAC.match(name)
        or _FALLBACK_RE_IP.match(name)
    )

from core.config import (
    ConfigError,
    get_fritz_credentials,
    get_fritz_host,
    resolve_network_type,
)
from core.events.event import Event, EventType, Severity, new_event
from harness.audit.writer import AuditWriter

_log = logging.getLogger(__name__)

_STATE_FORMAT_VERSION = 1
_STATE_PATH = Path("data/fritzbox_state.json")
_EVENTS_DIR = Path("data")
_EVENT_SOURCE = "fritzbox"
_DEFAULT_AUDIT_BASE_DIR = "audit-logs"


# ---------------------------------------------------------------------- #
# Zustand
# ---------------------------------------------------------------------- #

def _empty_state() -> dict[str, Any]:
    return {"version": _STATE_FORMAT_VERSION, "hosts": {}}


def _load_state(path: Path = _STATE_PATH) -> dict[str, Any]:
    """Liest den letzten Zustand. Fehlt/korrupt/unbekannte Version -> leer."""
    if not path.exists():
        return _empty_state()
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        _log.warning("state unlesbar (%s): %s", path, exc)
        return _empty_state()
    if not isinstance(data, dict):
        _log.warning("state kein dict: %s", type(data).__name__)
        return _empty_state()
    if data.get("version") != _STATE_FORMAT_VERSION:
        _log.warning(
            "state-version unbekannt: %r (erwartet %d)",
            data.get("version"), _STATE_FORMAT_VERSION,
        )
        return _empty_state()
    if not isinstance(data.get("hosts"), dict):
        data["hosts"] = {}
    return data


def _save_state(state: dict[str, Any], path: Path = _STATE_PATH) -> None:
    """Atomar: tempfile im selben Verzeichnis + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------- #
# Fritz!Box
# ---------------------------------------------------------------------- #

def _fetch_hosts(
    host: str, user: str, password: str,
) -> list[dict[str, Any]]:
    """
    Liest die Host-Liste. Skip Hosts ohne MAC (A1113).

    Rueckgabe: [{"ip":..., "mac":..., "name":..., "active": bool}]
    """
    conn = FritzConnection(address=host, user=user, password=password)
    hosts = FritzHosts(fc=conn)
    out: list[dict[str, Any]] = []
    for h in hosts.get_hosts_info():
        mac = h.get("mac")
        if not mac:
            _log.warning(
                "host ohne mac: ip=%r name=%r -> skip",
                h.get("ip"), h.get("name"),
            )
            continue
        out.append({
            "ip": h.get("ip") or None,
            "mac": mac,
            "name": (
                _FALLBACK_SENTINEL
                if _is_fallback_name(h.get("name") or "")
                else (h.get("name") or "")
            ),
            # status ist bool (NewActive) laut fritzconnection-
            # Doku/Code. A1123-A1126 erfuellt. Defensive
            # bool()-Kapselung: toleriert auch 0/1/None.
            "active": bool(h.get("status")),
        })
    return out


# ---------------------------------------------------------------------- #
# Diff
# ---------------------------------------------------------------------- #

def _diff_and_emit(
    old_state: dict[str, Any],
    new_hosts: list[dict[str, Any]],
) -> list[Event]:
    """
    Erzeugt Events aus Diff alter Zustand <-> neue Host-Liste.

    - neu + aktiv             -> DEVICE_PRESENCE.
    - neu + inaktiv           -> nichts.
    - war aktiv, jetzt aktiv  -> nichts (ausser name/ip-Diff).
    - war aktiv, jetzt inaktiv-> DEVICE_OFFLINE.
    - war inaktiv, jetzt aktiv-> DEVICE_PRESENCE.
    - war inaktiv, jetzt inak -> nichts.

    Re-Presence (Punkt 68, Auflage 1778/1779):
    Wenn active unveraendert bleibt, aber name oder ip
    sich geaendert haben (Vergleich gegen old_state,
    normalisierte Werte), wird ebenfalls
    DEVICE_PRESENCE emittiert. Grund: Config-
    Aenderungen (Netz-Label, IP) greifen sonst erst
    beim naechsten echten Zustandswechsel.
    """
    events: list[Event] = []
    old_hosts = old_state.get("hosts") or {}
    for h in new_hosts:
        mac = h["mac"]
        was = old_hosts.get(mac)
        is_active = bool(h["active"])
        was_active = bool(was["active"]) if was else None

        event_type: str | None = None
        if was_active is None:
            if is_active:
                event_type = EventType.DEVICE_PRESENCE.value
        else:
            if was_active and not is_active:
                event_type = EventType.DEVICE_OFFLINE.value
            elif (not was_active) and is_active:
                event_type = EventType.DEVICE_PRESENCE.value
            elif is_active:
                # Re-Presence (Punkt 68): active unveraendert,
                # aber name oder ip haben sich geaendert.
                old_name = was.get("name") if isinstance(was, dict) else None
                old_ip = was.get("ip") if isinstance(was, dict) else None
                if (old_name != h.get("name")
                        or old_ip != h.get("ip")):
                    event_type = EventType.DEVICE_PRESENCE.value

        if event_type is None:
            continue

        events.append(new_event(
            source=_EVENT_SOURCE,
            event_type=event_type,
            severity=Severity.INFO,
            data={
                "identifier": mac,
                "ip": h["ip"],
                "mac": mac,
                "entity_name": h["name"],
                "network_type": resolve_network_type(h["ip"]),
            },
        ))
    return events


def _new_state(new_hosts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "version": _STATE_FORMAT_VERSION,
        "last_run": datetime.now(UTC).isoformat(),
        "hosts": {
            h["mac"]: {
                "ip": h["ip"],
                "name": h["name"],
                "active": bool(h["active"]),
            }
            for h in new_hosts
        },
    }


# ---------------------------------------------------------------------- #
# Events schreiben
# ---------------------------------------------------------------------- #

def _events_path(now: datetime | None = None) -> Path:
    ts = now or datetime.now(UTC)
    name = "events-" + ts.strftime("%Y-%m-%d") + ".jsonl"
    return _EVENTS_DIR / name


def _write_events(events: list[Event], path: Path) -> int:
    """
    Append-only. Eine JSON-Zeile pro Event. Rueckgabe: Anzahl.

    Neue Dateien mit Modus 0o640 (Konsistenz mit audit-logs).
    os.open + os.chmod als umask-Absicherung.
    Bestehende Dateien werden nicht geprueft (Variante A,
    A1254): der Fix greift ab der naechsten Tagesdatei.
    """
    if not events:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, mode=0o640,
    )
    try:
        os.chmod(path, 0o640)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            for e in events:
                fh.write(e.to_json())
                fh.write("\n")
    except Exception:
        os.close(fd)
        raise
    return len(events)


# ---------------------------------------------------------------------- #
# run
# ---------------------------------------------------------------------- #

def run(*, audit_base_dir: str | os.PathLike[str] = _DEFAULT_AUDIT_BASE_DIR) -> int:
    """
    Ein Lauf. Exit-Codes siehe Modul-Docstring.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    start = time.monotonic()

    try:
        user, password = get_fritz_credentials()
        host = get_fritz_host()
    except ConfigError as exc:
        _log.error("credentials/config fehlen: %s", exc)
        return 2

    try:
        new_hosts = _fetch_hosts(host, user, password)
    except Exception as exc:  # noqa: BLE001 - Fail closed: Exit 1
        _log.error("Fritz!Box nicht erreichbar (%s): %s", host, exc)
        return 1

    try:
        old_state = _load_state()
        events = _diff_and_emit(old_state, new_hosts)
        events_path = _events_path()
        written = _write_events(events, events_path)
        _save_state(_new_state(new_hosts))
    except OSError as exc:
        _log.error("Schreibfehler: %s", exc)
        return 3

    if written:
        duration_ms = int((time.monotonic() - start) * 1000)
        try:
            audit = AuditWriter(base_dir=audit_base_dir)
            audit.log(
                agent="security_ai",
                tool="fritzbox_watcher",
                policy_result="ALLOWED",
                permission_level=0,
                execution_status="OK",
                duration_ms=duration_ms,
                details={
                    "kind": "watcher_run",
                    "hosts_seen": len(new_hosts),
                    "events_written": written,
                    "duration_ms": duration_ms,
                },
            )
        except Exception as exc:  # noqa: BLE001 - Fail closed: Exit 3
            _log.error("audit-Schreibfehler: %s", exc)
            return 3

    _log.info(
        "watcher_run hosts_seen=%d events_written=%d",
        len(new_hosts), written,
    )
    return 0


if __name__ == "__main__":
    sys.exit(run())
