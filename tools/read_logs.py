"""
Tool: read_logs (duenne Version).

Validiert einen Log-Pfad und liefert ein Mock-Ergebnis in der
Form, die ein echter Reader spaeter liefern wird.

Kein echter Datei-Zugriff. Kein open(). Nur Validierung + Mock.
Marker "mock": True bleibt, bis der echte Reader eingebaut wird.

Signatur folgt dem AgentLoop: tool.func(**args).
Also: read_logs_run(path=..., max_lines=...).
"""
from __future__ import annotations

from datetime import UTC, datetime, timezone
from pathlib import Path
from typing import Any

from harness.permissions.levels import Level
from harness.tool_registry.tool import Tool, ToolArgumentError

# ---------------------------------------------------------------------- #
# Erlaubte Werte
# ---------------------------------------------------------------------- #

# Nur Pfade unter diesem Praefix sind erlaubt. Die Policy Engine
# prueft zusaetzlich gegen ctx.config["read_only_paths"]; das hier
# ist Defense in Depth.
_ALLOWED_PREFIX = "/var/log/"

_DEFAULT_MAX_LINES = 200
_MAX_LINES_LIMIT = 1000

_SHELL_CHARS = (";", "|", "&", "$", "`", "\n", "\r", ">", "<")


# ---------------------------------------------------------------------- #
# Validierung
# ---------------------------------------------------------------------- #

def _validate_path(path: Any) -> str:
    """
    Akzeptiert Pfade mit Whitespace am Rand (entfernt ihn).
    Lehnt Shell-Zeichen ab, auch mitten im Pfad.

    Grund fuer strip(): Nutzer lesen Pfade oft aus Dateien
    (mit \n am Ende) -- das soll kein Fehler sein.
    Grund fuer Shell-Zeichen-Check: Injection-Versuche muessen
    auch bei "sauberem" Pfad blockiert werden.
    """
    if not isinstance(path, str):
        raise ToolArgumentError(
            f"read_logs: 'path' muss ein String sein, "
            f"nicht {type(path).__name__}"
        )
    p = path.strip()
    if not p:
        raise ToolArgumentError("read_logs: 'path' darf nicht leer sein")
    if len(p) > 512:
        raise ToolArgumentError(
            f"read_logs: 'path' zu lang ({len(p)} > 512)"
        )
    for ch in _SHELL_CHARS:
        if ch in p:
            raise ToolArgumentError(
                f"read_logs: Shell-Metazeichen {ch!r} in 'path'"
            )
    if ".." in p:
        raise ToolArgumentError("read_logs: '..' in 'path' nicht erlaubt")
    if not p.startswith(_ALLOWED_PREFIX):
        raise ToolArgumentError(
            f"read_logs: 'path' muss unter {_ALLOWED_PREFIX!r} liegen"
        )
    return p


def _validate_max_lines(max_lines: Any) -> int:
    if not isinstance(max_lines, int) or isinstance(max_lines, bool):
        raise ToolArgumentError(
            f"read_logs: 'max_lines' muss int sein, "
            f"nicht {type(max_lines).__name__}"
        )
    if max_lines < 1 or max_lines > _MAX_LINES_LIMIT:
        raise ToolArgumentError(
            f"read_logs: 'max_lines' muss zwischen 1 und "
            f"{_MAX_LINES_LIMIT} liegen, war {max_lines}"
        )
    return max_lines


# ---------------------------------------------------------------------- #
# Tool-Funktion
# ---------------------------------------------------------------------- #

def read_logs_run(
    path: str,
    max_lines: int = _DEFAULT_MAX_LINES,
) -> dict[str, Any]:
    """
    Duenne Version von read_logs.

    Validiert Argumente, liefert ein Mock-Ergebnis in der Form
    des spaeteren echten Readers.
    """
    p = _validate_path(path)
    n = _validate_max_lines(max_lines)

    now = datetime.now(UTC).isoformat()
    return {
        "source": "mock",
        "tool": "read_logs",
        "path": str(Path(p)),
        "max_lines": n,
        "read_at": now,
        "lines": [],          # echt: Liste der Log-Zeilen
        "bytes_read": 0,      # echt: tatsaechliche Groesse
        "truncated": False,   # echt: True, wenn mehr als max_lines
    }


# ---------------------------------------------------------------------- #
# Tool-Definition
# ---------------------------------------------------------------------- #

READ_LOGS_TOOL = Tool(
    name="read_logs",
    level=Level.READ,
    func=read_logs_run,
    description=(
        "Liest die letzten Zeilen einer Log-Datei unter /var/log/. "
        "Duenne Version: validiert Argumente, kein echter Datei-Zugriff."
    ),
    version="0.1.0",
    sandbox_profile="read_only",
    allowed_args=frozenset({"path", "max_lines"}),
    returns="dict",
)


__all__ = [
    "READ_LOGS_TOOL",
    "read_logs_run",
]
