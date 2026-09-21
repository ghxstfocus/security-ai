"""
Tool: nmap_scan (duenne Version).

Validiert Argumente und liefert ein strukturiertes Mock-Ergebnis
in der Form, die ein echter nmap-Aufruf spaeter liefern wird.
Marker "mock": True bleibt, bis der echte subprocess-Aufruf
eingebaut wird.

Kein subprocess. Kein nmap-Binary. Nur Validierung + Mock.

Signatur folgt dem AgentLoop: tool.func(**args).
Also: nmap_scan_run(target=..., ports=..., scan_type=...).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool, ToolArgumentError


# ---------------------------------------------------------------------- #
# Erlaubte Werte
# ---------------------------------------------------------------------- #

_VALID_SCAN_TYPES = frozenset({
    "connect",      # TCP connect scan (-sT)
    "syn",          # SYN scan (-sS, braucht root)
    "ping",         # nur Erreichbarkeit
})

# Ports als "22,80,443", "22-1024" oder "22,80,1000-2000".
# Wir parsen das nicht selbst, sondern reichen es durch. Der echte
# nmap-Aufruf bekommt das Format direkt.
_MAX_PORTS_LEN = 512


# ---------------------------------------------------------------------- #
# Validierung
# ---------------------------------------------------------------------- #

def _validate_target(target: Any) -> str:
    if not isinstance(target, str):
        raise ToolArgumentError(
            f"nmap_scan: 'target' muss ein String sein, "
            f"nicht {type(target).__name__}"
        )
    t = target.strip()
    if not t:
        raise ToolArgumentError("nmap_scan: 'target' darf nicht leer sein")
    if len(t) > 253:
        raise ToolArgumentError(
            f"nmap_scan: 'target' zu lang ({len(t)} > 253)"
        )
    return t


def _validate_ports(ports: Any) -> str | None:
    if ports is None:
        return None
    if isinstance(ports, (list, tuple)):
        # Bequemlichkeit: [22, 80] -> "22,80"
        try:
            ports = ",".join(str(int(p)) for p in ports)
        except (TypeError, ValueError) as exc:
            raise ToolArgumentError(
                "nmap_scan: 'ports' als Liste muss Zahlen enthalten"
            ) from exc
    if not isinstance(ports, str):
        raise ToolArgumentError(
            f"nmap_scan: 'ports' muss String oder Liste sein, "
            f"nicht {type(ports).__name__}"
        )
    p = ports.strip()
    if not p:
        return None
    if len(p) > _MAX_PORTS_LEN:
        raise ToolArgumentError(
            f"nmap_scan: 'ports' zu lang ({len(p)} > {_MAX_PORTS_LEN})"
        )
    # Nur Ziffern, Komma, Bindestrich erlaubt (nmap-Syntax)
    for ch in p:
        if not (ch.isdigit() or ch in ",-"):
            raise ToolArgumentError(
                f"nmap_scan: unerlaubtes Zeichen {ch!r} in 'ports'"
            )
    return p


def _validate_scan_type(scan_type: Any) -> str:
    if not isinstance(scan_type, str):
        raise ToolArgumentError(
            f"nmap_scan: 'scan_type' muss String sein, "
            f"nicht {type(scan_type).__name__}"
        )
    st = scan_type.strip().lower()
    if st not in _VALID_SCAN_TYPES:
        raise ToolArgumentError(
            f"nmap_scan: unbekannter scan_type {st!r}. "
            f"Erlaubt: {sorted(_VALID_SCAN_TYPES)}"
        )
    return st


# ---------------------------------------------------------------------- #
# Tool-Funktion
# ---------------------------------------------------------------------- #

def nmap_scan_run(
    target: str,
    ports: str | list[int] | None = None,
    scan_type: str = "connect",
) -> dict[str, Any]:
    """
    Duenne Version von nmap_scan.

    Validiert Argumente, liefert ein Mock-Ergebnis in der Form
    des spaeteren echten Nmap-Outputs.
    """
    t = _validate_target(target)
    p = _validate_ports(ports)
    st = _validate_scan_type(scan_type)

    now = datetime.now(timezone.utc).isoformat()

    return {
        "mock": True,
        "tool": "nmap_scan",
        "target": t,
        "ports": p,
        "scan_type": st,
        "started_at": now,
        "finished_at": now,
        "command_hint": _command_hint(t, p, st),
        "hosts": [],          # echt: Liste von Hosts mit offenen Ports
        "stdout_summary": (
            f"mock scan: target={t} ports={p or 'default'} type={st}"
        ),
    }


def _command_hint(target: str, ports: str | None, scan_type: str) -> str:
    """Gibt den Kommando-Vorschlag zurueck (nur Doku, nicht ausgefuehrt)."""
    flag = {
        "connect": "-sT",
        "syn": "-sS",
        "ping": "-sn",
    }[scan_type]
    parts = ["nmap", flag]
    if ports:
        parts += ["-p", ports]
    parts.append(target)
    return " ".join(parts)


# ---------------------------------------------------------------------- #
# Tool-Definition
# ---------------------------------------------------------------------- #

NMAP_SCAN_TOOL = Tool(
    name="nmap_scan",
    level=Level.SECURITY_ACTION,
    func=nmap_scan_run,
    description=(
        "Nmap-Scan gegen ein autorisiertes Ziel. "
        "Duenne Version: validiert Argumente, kein echter subprocess."
    ),
    version="0.1.0",
    sandbox_profile="nmap_local",
    allowed_args=frozenset({"target", "ports", "scan_type"}),
    returns="dict",
)


__all__ = [
    "NMAP_SCAN_TOOL",
    "nmap_scan_run",
]
