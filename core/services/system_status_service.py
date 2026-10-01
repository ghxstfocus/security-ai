"""
SystemStatusService — Snapshot fuer /system (Punkt 66).

Kategorie 3 (Service, RBAC, subprocess mit
dokumentierter Ausnahme §N).

- RBAC: device.read vor jedem Zugriff.
- psutil: CPU, RAM, Disk, Load, Uptime.
- Services-Status: subprocess.run systemctl is-active
  fuer eine feste Unit-Whitelist.
- Ausnahme §N (Punkt 66, Auflage 1753):
  nur eigene security-ai-Units, Argument-Whitelist,
  shell=False, timeout=2, check=False.
  Kein Shell-String, kein ;, kein |.
- Fail closed: Fehler -> "unbekannt", kein 500.
"""
from __future__ import annotations

import logging
import subprocess
import time
from typing import Any

import psutil

from core.access.checker import AccessChecker

log = logging.getLogger(__name__)

UNIT_WHITELIST: tuple[str, ...] = (
    "security-ai-dashboard.service",
    "security-ai-event-reader.service",
    "security-ai-fritzbox-watcher.service",
)

_SYSTEMCTL_BIN = "systemctl"
_SYSTEMCTL_TIMEOUT_S = 2


def _safe_psutil() -> dict[str, Any]:
    """psutil-Werte. Bei Fehler einzelne Felder None."""
    out: dict[str, Any] = {
        "cpu_percent": None,
        "cpu_count": None,
        "ram_percent": None,
        "ram_used_gb": None,
        "ram_total_gb": None,
        "disk_root_percent": None,
        "disk_root_used_gb": None,
        "disk_root_total_gb": None,
        "loadavg_1": None,
        "loadavg_5": None,
        "loadavg_15": None,
        "uptime_seconds": None,
    }
    try:
        out["cpu_percent"] = float(psutil.cpu_percent(interval=0.1))
        out["cpu_count"] = int(psutil.cpu_count() or 0)
    except Exception as exc:  # noqa: BLE001 - Anzeige fail open
        log.debug("psutil cpu: %s", exc)
    try:
        vm = psutil.virtual_memory()
        out["ram_percent"] = float(vm.percent)
        out["ram_used_gb"] = round(vm.used / (1024 ** 3), 1)
        out["ram_total_gb"] = round(vm.total / (1024 ** 3), 1)
    except Exception as exc:  # noqa: BLE001
        log.debug("psutil ram: %s", exc)
    try:
        du = psutil.disk_usage("/")
        out["disk_root_percent"] = float(du.percent)
        out["disk_root_used_gb"] = round(du.used / (1024 ** 3), 1)
        out["disk_root_total_gb"] = round(du.total / (1024 ** 3), 1)
    except Exception as exc:  # noqa: BLE001
        log.debug("psutil disk: %s", exc)
    try:
        la = psutil.getloadavg()
        out["loadavg_1"] = round(la[0], 2)
        out["loadavg_5"] = round(la[1], 2)
        out["loadavg_15"] = round(la[2], 2)
    except Exception as exc:  # noqa: BLE001
        log.debug("psutil loadavg: %s", exc)
    try:
        out["uptime_seconds"] = int(time.time() - psutil.boot_time())
    except Exception as exc:  # noqa: BLE001
        log.debug("psutil boot_time: %s", exc)
    return out


def _systemctl_is_active(unit: str) -> str:
    """is-active fuer eine Unit aus der Whitelist.

    Fail closed: jeder Fehler -> "unbekannt".
    """
    if unit not in UNIT_WHITELIST:
        return "unbekannt"
    argv = [_SYSTEMCTL_BIN, "is-active", unit]
    try:
        proc = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=_SYSTEMCTL_TIMEOUT_S,
            check=False,
        )
    except Exception:  # noqa: BLE001 - fail closed
        return "unbekannt"
    raw = (proc.stdout or "").strip()
    if raw in ("active", "inactive", "failed", "activating",
               "deactivating", "reloading"):
        return raw
    return "unbekannt"


class SystemStatusServiceError(RuntimeError):
    """Service-Fehler (RBAC, Konstruktor)."""


class SystemStatusOperationError(RuntimeError):
    """Betriebsfehler (kein psutil, kein subprocess)."""


class SystemStatusService:
    def __init__(self, *, checker: AccessChecker) -> None:
        if checker is None:
            raise SystemStatusOperationError(
                "SystemStatusService: checker fehlt"
            )
        self._checker = checker

    def _require(self, actor: str, code: str) -> None:
        self._checker.require_permission(actor, code)

    def get_snapshot(self, actor: str) -> dict[str, Any]:
        """Snapshot aus psutil + Services-Status. RBAC device.read."""
        self._require(actor, "device.read")
        data = _safe_psutil()
        services = [
            {"unit": u, "status": _systemctl_is_active(u)}
            for u in UNIT_WHITELIST
        ]
        data["services"] = services
        data["available"] = True
        return data


__all__ = [
    "UNIT_WHITELIST",
    "SystemStatusOperationError",
    "SystemStatusService",
    "SystemStatusServiceError",
]
