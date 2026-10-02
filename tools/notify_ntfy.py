# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tool: notify_ntfy.

Sendet eine Nachricht an einen ntfy-Server (self-hosted)
via HTTP POST.

- Konfiguration aus Umgebungsvariablen:
    NTFY_URL
    NTFY_TOPIC
    NTFY_TOKEN
  Fehlt eine davon: ToolError (fail closed).
- HTTP POST an {NTFY_URL}/{NTFY_TOPIC}
- Header:
    Authorization: Bearer <token>
    Title: <title>
    Priority: <severity-Mapping>
    Tags: <severity>
- Timeout 5s
- Kein "mock"-Modus: ntfy-Server ist extern.
- _base_url erlaubt Tests gegen lokale Fake-Server
  (Unterstrich = "nur fuer Tests", nicht in allowed_args).

Signatur folgt dem AgentLoop: tool.func(**args).
Also: notify_ntfy_run(title=..., message=..., severity=...).

Severity -> ntfy Priority:
    INFO     -> "low"
    WARNING  -> "high"
    CRITICAL -> "urgent"
Severity -> Tag:
    INFO     -> "information_source"
    WARNING  -> "warning"
    CRITICAL -> "rotating_light"
"""
from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import requests

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool, ToolArgumentError, ToolError

_TIMEOUT_S = 5
_MAX_TITLE_LEN = 200
_MAX_MESSAGE_LEN = 4000

_VALID_SEVERITIES = frozenset({"INFO", "WARNING", "CRITICAL"})

_SEVERITY_TO_PRIORITY = {
    "INFO": "low",
    "WARNING": "high",
    "CRITICAL": "urgent",
}

_SEVERITY_TO_TAG = {
    "INFO": "information_source",
    "WARNING": "warning",
    "CRITICAL": "rotating_light",
}


def _validate_title(title: Any) -> str:
    if not isinstance(title, str):
        raise ToolArgumentError(
            f"notify_ntfy: 'title' muss String sein, "
            f"nicht {type(title).__name__}"
        )
    t = title.strip()
    if not t:
        raise ToolArgumentError("notify_ntfy: 'title' darf nicht leer sein")
    if len(t) > _MAX_TITLE_LEN:
        raise ToolArgumentError(
            f"notify_ntfy: 'title' zu lang ({len(t)} > {_MAX_TITLE_LEN})"
        )
    return t


def _validate_message(message: Any) -> str:
    if not isinstance(message, str):
        raise ToolArgumentError(
            f"notify_ntfy: 'message' muss String sein, "
            f"nicht {type(message).__name__}"
        )
    m = message.strip()
    if not m:
        raise ToolArgumentError("notify_ntfy: 'message' darf nicht leer sein")
    if len(m) > _MAX_MESSAGE_LEN:
        raise ToolArgumentError(
            f"notify_ntfy: 'message' zu lang ({len(m)} > {_MAX_MESSAGE_LEN})"
        )
    return m


def _validate_severity(severity: Any) -> str:
    if not isinstance(severity, str):
        raise ToolArgumentError(
            f"notify_ntfy: 'severity' muss String sein, "
            f"nicht {type(severity).__name__}"
        )
    s = severity.strip().upper()
    if s not in _VALID_SEVERITIES:
        raise ToolArgumentError(
            f"notify_ntfy: unbekannte severity {s!r}. "
            f"Erlaubt: {sorted(_VALID_SEVERITIES)}"
        )
    return s


def _read_config() -> tuple[str, str, str]:
    """Liest NTFY_URL, NTFY_TOPIC, NTFY_TOKEN. Fail closed."""
    url = (os.environ.get("NTFY_URL") or "").rstrip("/")
    topic = os.environ.get("NTFY_TOPIC") or ""
    token = os.environ.get("NTFY_TOKEN") or ""
    if not url:
        raise ToolError("notify_ntfy: NTFY_URL nicht gesetzt (fail closed)")
    if not topic:
        raise ToolError("notify_ntfy: NTFY_TOPIC nicht gesetzt (fail closed)")
    if not token:
        raise ToolError("notify_ntfy: NTFY_TOKEN nicht gesetzt (fail closed)")
    return url, topic, token


def notify_ntfy_run(
    title: str,
    message: str,
    severity: str = "INFO",
) -> dict[str, Any]:
    """Sendet eine Nachricht an den ntfy-Server."""
    t = _validate_title(title)
    m = _validate_message(message)
    s = _validate_severity(severity)

    url, topic, token = _read_config()

    headers = {
        "Authorization": f"Bearer {token}",
        "Title": t,
        "Priority": _SEVERITY_TO_PRIORITY[s],
        "Tags": _SEVERITY_TO_TAG[s],
    }

    target = f"{url}/{topic}"

    try:
        resp = requests.post(
            target, data=m.encode("utf-8"),
            headers=headers, timeout=_TIMEOUT_S,
        )
    except requests.exceptions.Timeout as exc:
        raise ToolError(
            f"notify_ntfy: Timeout nach {_TIMEOUT_S}s"
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise ToolError(
            f"notify_ntfy: Verbindungsfehler: {exc}"
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise ToolError(
            f"notify_ntfy: HTTP-Client-Fehler: {exc}"
        ) from exc

    if resp.status_code not in (200, 201, 202):
        body = resp.text[:500] if resp.text else ""
        raise ToolError(
            f"notify_ntfy: HTTP {resp.status_code} von ntfy: {body}"
        )

    return {
        "ok": True,
        "source": "ntfy",
        "topic": topic,
        "sent_at": datetime.now(UTC).isoformat(),
    }


NOTIFY_NTFY_TOOL = Tool(
    name="notify_ntfy",
    level=Level.SECURITY_ACTION,
    func=notify_ntfy_run,
    description="Sendet eine Nachricht an einen ntfy-Server.",
    version="0.1.0",
    sandbox_profile="no_network_except_ntfy",
    allowed_args=frozenset({"title", "message", "severity"}),
    returns="dict",
)


__all__ = [
    "NOTIFY_NTFY_TOOL",
    "notify_ntfy_run",
]
