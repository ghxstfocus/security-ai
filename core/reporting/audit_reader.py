"""
Audit-Reader.

Liest JSONL-Audit-Logs (audit-logs/YYYY-MM-DD.jsonl) und
liefert gefilterte Eintraege als dicts.

Kein DB-Zugriff. Kein Schreiben. Nur lesen und filtern.

Fail-soft: korrupte Zeilen werden uebersprungen und gezaehlt.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DEFAULT_AUDIT_DIR = "audit-logs"


class AuditJsonlError(RuntimeError):
    """Schwerer Fehler beim Lesen (z. B. Verzeichnis fehlt)."""


# ---------------------------------------------------------------------- #
# interne Helfer
# ---------------------------------------------------------------------- #

def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt


def _iter_jsonl_lines(paths: Iterable[Path]):
    """
    Liefert (lineno, line) fuer jede nicht-leere Zeile.
    Oeffnet jede Datei einmal. Kein raise bei OSError.
    """
    for p in paths:
        try:
            with p.open(encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, start=1):
                    s = line.strip()
                    if s:
                        yield (p, lineno, s)
        except OSError:
            continue


def _iter_entries(
    base_dir: Path,
    *,
    since: datetime,
    now: datetime,
) -> tuple[list[dict[str, Any]], int]:
    """
    Liefert (entries, skipped) aus allen JSONL-Dateien in base_dir.
    Filtert auf timestamp >= since und timestamp <= now.
    """
    entries: list[dict[str, Any]] = []
    skipped = 0
    if not base_dir.is_dir():
        return (entries, skipped)

    paths = sorted(base_dir.glob("*.jsonl"))
    for _p, _lineno, line in _iter_jsonl_lines(paths):
        try:
            obj = json.loads(line)
        except (TypeError, ValueError):
            skipped += 1
            continue
        if not isinstance(obj, dict):
            skipped += 1
            continue
        ts = _parse_ts(obj.get("timestamp"))
        if ts is None:
            skipped += 1
            continue
        if ts < since or ts > now:
            continue
        entries.append(obj)
    return (entries, skipped)


# ---------------------------------------------------------------------- #
# oeffentliche API
# ---------------------------------------------------------------------- #

def read_risk_assessments(
    base_dir: str | Path = DEFAULT_AUDIT_DIR,
    *,
    since_hours: int = 24,
    max_entries: int = 50,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """
    Liefert risk_assessment-Eintraege der letzten since_hours,
    neueste zuerst, maximal max_entries.

    Pro Eintrag kompaktes dict:
        {
          "audit_id": str | None,
          "timestamp": str | None,
          "event_id": str | None,
          "category": str | None,
          "score": float | None,
          "rule_id": str | None,
          "tool": str | None,
        }
    """
    if since_hours < 0:
        raise ValueError("since_hours muss >= 0 sein")
    if max_entries <= 0:
        return []

    now_dt = now or datetime.now(UTC)
    since = now_dt - timedelta(hours=since_hours)

    entries, _skipped = _iter_entries(
        Path(base_dir), since=since, now=now_dt,
    )

    result: list[dict[str, Any]] = []
    for obj in entries:
        details = obj.get("details")
        if not isinstance(details, dict):
            continue
        if details.get("kind") != "risk_assessment":
            continue
        result.append({
            "audit_id": obj.get("audit_id"),
            "timestamp": obj.get("timestamp"),
            "event_id": details.get("event_id"),
            "category": details.get("category"),
            "score": details.get("score"),
            "rule_id": details.get("rule_id"),
            "tool": obj.get("tool"),
        })

    # Neueste zuerst
    result.sort(
        key=lambda e: e.get("timestamp") or "",
        reverse=True,
    )
    return result[:max_entries]


def count_by_category(
    entries: list[dict[str, Any]],
) -> dict[str, int]:
    """Zaehlt Eintraege pro category."""
    counts: dict[str, int] = {}
    for e in entries:
        cat = e.get("category")
        if not isinstance(cat, str) or not cat:
            cat = "UNKNOWN"
        counts[cat] = counts.get(cat, 0) + 1
    return counts


__all__ = [
    "DEFAULT_AUDIT_DIR",
    "AuditJsonlError",
    "count_by_category",
    "read_risk_assessments",
]
