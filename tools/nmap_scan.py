# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tool: nmap_scan (echte Version).

Ruft nmap per subprocess auf, mit Sandbox:
  - shell=False, Argumentliste
  - Timeout 30s
  - Argument-Whitelist (-sT, -sV, -p, --top-ports, -oX, -Pn, -n)
  - Ziel-Whitelist via ipaddress (fail closed)
  - XML-Ausgabe auf stdout (-oX -), Parsing mit defusedxml.ElementTree

Ziel-Whitelist (Defense in Depth, identisch zur Policy):
  localhost, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

Signatur folgt dem AgentLoop: tool.func(**args).
Also: nmap_scan_run(target=..., ports=..., scan_type=...).
"""
from __future__ import annotations

import shutil
import subprocess
from datetime import UTC, datetime
from typing import Any

from defusedxml import ElementTree as ET

from core.net.scope import check_target_allowed
from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool, ToolArgumentError, ToolError

# ---------------------------------------------------------------------- #
# Konstanten
# ---------------------------------------------------------------------- #

_NMAP_BIN = "nmap"
_NMAP_TIMEOUT_S = 30

_ALLOWED_SCAN_TYPES = frozenset({"connect"})
_FORBIDDEN_SCAN_TYPES = {
    "syn": "syn scan nicht erlaubt, braucht root",
    "ping": "ping scan nicht in der Whitelist",
}

# Nur diese Flags darf der Builder setzen. Alles andere -> ToolError.
_ARG_WHITELIST = frozenset({
    "-sT", "-sV", "-p", "--top-ports", "-oX", "-Pn", "-n",
})

# Ziel-Whitelist als Netz-Objekte.

_MAX_PORTS_LEN = 512
_MAX_TARGET_LEN = 253


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
    if len(t) > _MAX_TARGET_LEN:
        raise ToolArgumentError(
            f"nmap_scan: 'target' zu lang ({len(t)} > {_MAX_TARGET_LEN})"
        )
    return t


def _validate_ports(ports: Any) -> str | None:
    if ports is None:
        return None
    if isinstance(ports, (list, tuple)):
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
    if st in _FORBIDDEN_SCAN_TYPES:
        raise ToolError(f"nmap_scan: {_FORBIDDEN_SCAN_TYPES[st]}")
    if st not in _ALLOWED_SCAN_TYPES:
        raise ToolArgumentError(
            f"nmap_scan: unbekannter scan_type {st!r}. "
            f"Erlaubt: {sorted(_ALLOWED_SCAN_TYPES)}"
        )
    return st


# ---------------------------------------------------------------------- #
# Argument-Bau (Whitelist)
# ---------------------------------------------------------------------- #

def _build_argv(target: str, ports: str | None, scan_type: str) -> list[str]:
    argv: list[str] = [_NMAP_BIN, "-sT", "-oX", "-", "-Pn", "-n"]
    if scan_type == "connect":
        pass  # -sT ist schon drin
    else:
        raise ToolError(
            f"nmap_scan: scan_type {scan_type!r} hat kein Flag-Mapping"
        )
    if ports:
        argv += ["-p", ports]
    argv.append(target)
    for a in argv:
        if a.startswith("-") and a not in _ARG_WHITELIST and a not in {"-"}:
            raise ToolError(f"nmap_scan: Argument {a!r} nicht in Whitelist")
    return argv


# ---------------------------------------------------------------------- #
# XML-Parsing
# ---------------------------------------------------------------------- #

def _parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ToolError(f"nmap_scan: XML-Parse-Fehler: {exc}") from exc

    hosts: list[dict[str, Any]] = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        ip = addr_el.get("addr") if addr_el is not None else None

        hostname = None
        hn_el = host.find("hostnames/hostname")
        if hn_el is not None:
            hostname = hn_el.get("name")

        state = None
        st_el = host.find("status")
        if st_el is not None:
            state = st_el.get("state")

        ports: list[dict[str, Any]] = []
        for port in host.findall("ports/port"):
            proto = port.get("protocol")
            portid = port.get("portid")
            pstate = None
            ps_el = port.find("state")
            if ps_el is not None:
                pstate = ps_el.get("state")
            service = None
            product = None
            version = None
            svc_el = port.find("service")
            if svc_el is not None:
                service = svc_el.get("name")
                product = svc_el.get("product")
                version = svc_el.get("version")
            try:
                portnum = int(portid) if portid is not None else None
            except ValueError:
                portnum = None
            ports.append({
                "port": portnum,
                "protocol": proto,
                "state": pstate,
                "service": service,
                "product": product,
                "version": version,
            })

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "state": state,
            "ports": ports,
        })
    return hosts


# ---------------------------------------------------------------------- #
# Tool-Funktion
# ---------------------------------------------------------------------- #

def nmap_scan_run(
    target: str,
    ports: str | list[int] | None = None,
    scan_type: str = "connect",
) -> dict[str, Any]:
    """
    Echter nmap-Aufruf mit Sandbox.

    Fail closed bei:
      - fehlendem nmap-Binary
      - nicht erlaubtem Ziel
      - Timeout
      - non-zero exit
      - XML-Parse-Fehler
    """
    t = _validate_target(target)
    p = _validate_ports(ports)
    st = _validate_scan_type(scan_type)

    check_target_allowed(t)

    if shutil.which(_NMAP_BIN) is None:
        raise ToolError(
            f"nmap_scan: {_NMAP_BIN!r} nicht im PATH. "
            "Siehe docs/DEPLOYMENT.md (apt install nmap)."
        )

    argv = _build_argv(t, p, st)

    started = datetime.now(UTC)

    try:
        proc = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=_NMAP_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolError(
            f"nmap_scan: Timeout nach {_NMAP_TIMEOUT_S}s"
        ) from exc
    except FileNotFoundError as exc:
        raise ToolError(
            f"nmap_scan: {_NMAP_BIN!r} nicht ausfuehrbar: {exc}"
        ) from exc
    except OSError as exc:
        raise ToolError(f"nmap_scan: OSError: {exc}") from exc

    finished = datetime.now(UTC)

    if proc.returncode != 0:
        raise ToolError(
            f"nmap_scan: nmap exit {proc.returncode}: "
            f"{(proc.stderr or '').strip()[:200]}"
        )

    hosts = _parse_nmap_xml(proc.stdout or "")

    return {
        "source": "nmap",
        "tool": "nmap_scan",
        "target": t,
        "ports": p,
        "scan_type": st,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "argv": argv,
        "hosts": hosts,
        "stdout_summary": (
            f"nmap scan: target={t} ports={p or 'default'} "
            f"hosts={len(hosts)}"
        ),
    }


# ---------------------------------------------------------------------- #
# Tool-Definition
# ---------------------------------------------------------------------- #

NMAP_SCAN_TOOL = Tool(
    name="nmap_scan",
    level=Level.SECURITY_ACTION,
    func=nmap_scan_run,
    description=(
        "Nmap-Scan gegen ein autorisiertes Ziel. "
        "Echte Ausfuehrung via subprocess mit Sandbox "
        "(Timeout, Argument-Whitelist, Ziel-Whitelist, XML-Parsing)."
    ),
    version="0.2.0",
    sandbox_profile="nmap_local",
    allowed_args=frozenset({"target", "ports", "scan_type"}),
    returns="dict",
)


__all__ = [
    "NMAP_SCAN_TOOL",
    "nmap_scan_run",
]
