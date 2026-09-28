"""
Tool: telegram_alert.

Sendet eine Nachricht an einen Telegram-Chat via Bot-API.

- Token und Chat-ID aus Umgebungsvariablen:
    TELEGRAM_BOT_TOKEN
    TELEGRAM_CHAT_ID
  Fehlt eine davon: ToolError (fail closed).
- HTTP-POST an {base}/bot{token}/sendMessage mit requests
- Timeout 5s
- Kein "mock"-Modus: Telegram-API ist extern.
- _base_url erlaubt Tests gegen lokale Fake-Server
  (Unterstrich = "nur fuer Tests", nicht in allowed_args).

Signatur folgt dem AgentLoop: tool.func(**args).
Also: telegram_alert_run(title=..., message=..., severity=...).
"""
from __future__ import annotations

import os
from datetime import UTC, datetime, timezone
from typing import Any

import requests

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool, ToolArgumentError, ToolError

_DEFAULT_BASE_URL = "https://api.telegram.org"
_TIMEOUT_S = 5
_MAX_TITLE_LEN = 200
_MAX_MESSAGE_LEN = 4000

_VALID_SEVERITIES = frozenset({"INFO", "WARNING", "CRITICAL"})

_SEVERITY_PREFIX = {
    "INFO": "[i]",
    "WARNING": "[!]",
    "CRITICAL": "[X]",
}


# ---------------------------------------------------------------------- #
# Validierung
# ---------------------------------------------------------------------- #

def _validate_title(title: Any) -> str:
    if not isinstance(title, str):
        raise ToolArgumentError(
            f"telegram_alert: 'title' muss String sein, "
            f"nicht {type(title).__name__}"
        )
    t = title.strip()
    if not t:
        raise ToolArgumentError("telegram_alert: 'title' darf nicht leer sein")
    if len(t) > _MAX_TITLE_LEN:
        raise ToolArgumentError(
            f"telegram_alert: 'title' zu lang ({len(t)} > {_MAX_TITLE_LEN})"
        )
    return t


def _validate_message(message: Any) -> str:
    if not isinstance(message, str):
        raise ToolArgumentError(
            f"telegram_alert: 'message' muss String sein, "
            f"nicht {type(message).__name__}"
        )
    m = message.strip()
    if not m:
        raise ToolArgumentError("telegram_alert: 'message' darf nicht leer sein")
    if len(m) > _MAX_MESSAGE_LEN:
        raise ToolArgumentError(
            f"telegram_alert: 'message' zu lang ({len(m)} > {_MAX_MESSAGE_LEN})"
        )
    return m


def _validate_severity(severity: Any) -> str:
    if not isinstance(severity, str):
        raise ToolArgumentError(
            f"telegram_alert: 'severity' muss String sein, "
            f"nicht {type(severity).__name__}"
        )
    s = severity.strip().upper()
    if s not in _VALID_SEVERITIES:
        raise ToolArgumentError(
            f"telegram_alert: unbekannte severity {s!r}. "
            f"Erlaubt: {sorted(_VALID_SEVERITIES)}"
        )
    return s


def _validate_base_url(base_url: Any) -> str:
    if not isinstance(base_url, str):
        raise ToolArgumentError(
            f"telegram_alert: '_base_url' muss String sein, "
            f"nicht {type(base_url).__name__}"
        )
    b = base_url.strip().rstrip("/")
    if not b:
        raise ToolArgumentError("telegram_alert: '_base_url' darf nicht leer sein")
    return b


# ---------------------------------------------------------------------- #
# Tool-Funktion
# ---------------------------------------------------------------------- #

def telegram_alert_run(
    title: str,
    message: str,
    severity: str = "INFO",
    _base_url: str | None = None,
) -> dict[str, Any]:
    """Sendet eine Nachricht an Telegram."""
    t = _validate_title(title)
    m = _validate_message(message)
    s = _validate_severity(severity)

    base = _validate_base_url(_base_url or _DEFAULT_BASE_URL)

    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token:
        raise ToolError(
            "telegram_alert: TELEGRAM_BOT_TOKEN nicht gesetzt (fail closed)"
        )
    if not chat_id:
        raise ToolError(
            "telegram_alert: TELEGRAM_CHAT_ID nicht gesetzt (fail closed)"
        )

    prefix = _SEVERITY_PREFIX[s]
    text = f"{prefix} {t}\n\n{m}"

    url = f"{base}/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
    }

    try:
        resp = requests.post(url, json=payload, timeout=_TIMEOUT_S)
    except requests.exceptions.Timeout as exc:
        raise ToolError(
            f"telegram_alert: Timeout nach {_TIMEOUT_S}s"
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise ToolError(
            f"telegram_alert: Verbindungsfehler: {exc}"
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise ToolError(
            f"telegram_alert: HTTP-Client-Fehler: {exc}"
        ) from exc

    if resp.status_code != 200:
        body = resp.text[:500] if resp.text else ""
        raise ToolError(
            f"telegram_alert: HTTP {resp.status_code} von Telegram-API: {body}"
        )

    try:
        data = resp.json()
    except ValueError as exc:
        raise ToolError("telegram_alert: Antwort ist kein JSON") from exc

    if not isinstance(data, dict) or not data.get("ok"):
        desc = data.get("description", "unbekannt") if isinstance(data, dict) else str(data)
        raise ToolError(
            f"telegram_alert: Telegram-API meldet Fehler: {desc}"
        )

    result = data.get("result") or {}
    message_id = result.get("message_id")
    if not isinstance(message_id, int):
        raise ToolError("telegram_alert: message_id fehlt in Antwort")

    return {
        "ok": True,
        "message_id": message_id,
        "source": "telegram",
        "sent_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------- #
# Tool-Definition
# ---------------------------------------------------------------------- #

TELEGRAM_ALERT_TOOL = Tool(
    name="telegram_alert",
    level=Level.SECURITY_ACTION,
    func=telegram_alert_run,
    description="Sendet eine Nachricht an einen Telegram-Chat.",
    version="0.1.0",
    sandbox_profile="no_network_except_telegram",
    allowed_args=frozenset({"title", "message", "severity"}),
    returns="dict",
)


__all__ = [
    "TELEGRAM_ALERT_TOOL",
    "telegram_alert_run",
]
