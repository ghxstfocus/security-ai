# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Event-Reader: liest Events aus der Tagesdatei und
uebergibt sie an die Security AI.

Eingang:
    data/events-YYYY-MM-DD.jsonl (UTC-Datum), JSONL,
    eine Event-Zeile pro Zeile (Event.to_json()).

Ausgang:
    SecurityAI.process(event) pro Event.
    Cursor in DB (event_cursor: file_name + line_offset).
    Idempotenz-Marker in DB (processed_events: event_id).

Lauf-Modell:
    systemd-Timer, OnUnitActiveSec=30s, OnBootSec=60s.
    Kein Dauerprozess.

Fail closed:
    Exit 0: OK (auch bei 0 Events).
    Exit 1: check_audit_logs fehlgeschlagen.
    Exit 2: check_schema_version fehlgeschlagen.
    Exit 3: Event-Processing-Fehler (process warf).
    Exit 4: Datei/IO-Fehler (Event-Datei oder Cursor).

CWD muss /opt/security-ai sein (Default-Pfade relativ).
"""
from __future__ import annotations

import json
import logging
import os
import pwd
import sqlite3
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from apps.security_ai.orchestrator import SecurityAI
from core.events.event import Event
from core.inventory.repository import (
    DEFAULT_DB_PATH,
    DEFAULT_MIGRATIONS_DIR,
    SchemaVersionError,
    check_schema_version,
    connect,
)
from harness.audit.writer import (
    AuditDirInconsistentError,
    check_audit_logs,
)

_log = logging.getLogger(__name__)

_EVENTS_DIR = Path("data")
_AUDIT_BASE_DIR = "audit-logs"
PROCESSED_EVENTS_MAX_AGE_DAYS = 30


# ---------------------------------------------------------------------- #
# Cursor
# ---------------------------------------------------------------------- #

def _read_cursor(conn: sqlite3.Connection) -> tuple[str, int]:
    """Liest (file_name, line_offset) aus event_cursor (id=1)."""
    row = conn.execute(
        "SELECT file_name, line_offset FROM event_cursor WHERE id = 1"
    ).fetchone()
    if row is None:
        # Default-Zeile anlegen (Migration hat sie bereits,
        # aber fail-safe, falls die Tabelle manuell geleert wurde).
        conn.execute(
            "INSERT OR IGNORE INTO event_cursor "
            "(id, file_name, line_offset, updated_at) "
            "VALUES (1, '', 0, ?)",
            (datetime.now(UTC).isoformat(),),
        )
        conn.commit()
        return ("", 0)
    return (str(row[0] or ""), int(row[1] or 0))


def _write_cursor(
    conn: sqlite3.Connection, file_name: str, line_offset: int,
) -> None:
    """Aktualisiert den Cursor (eine Zeile, id=1)."""
    conn.execute(
        "UPDATE event_cursor SET file_name = ?, line_offset = ?, "
        "updated_at = ? WHERE id = 1",
        (file_name, line_offset, datetime.now(UTC).isoformat()),
    )
    conn.commit()


# ---------------------------------------------------------------------- #
# Pfad + Zeilen
# ---------------------------------------------------------------------- #

def _current_events_path(now: datetime | None = None) -> Path:
    ts = now or datetime.now(UTC)
    return _EVENTS_DIR / ("events-" + ts.strftime("%Y-%m-%d") + ".jsonl")


def _read_new_lines(path: Path, offset: int) -> list[str]:
    """
    Liest Zeilen ab offset. Wenn die Datei fehlt oder kleiner ist
    als offset: leere Liste. Wenn offset > Anzahl Zeilen: leere Liste.
    """
    if not path.exists():
        return []
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OSError(f"events-Datei unlesbar: {path}: {exc}") from exc
    lines = raw.splitlines()
    return lines[offset:]


# ---------------------------------------------------------------------- #
# Idempotenz-Marker
# ---------------------------------------------------------------------- #

def _mark_processing(
    conn: sqlite3.Connection, event_id: str,
) -> bool:
    """INSERT OR IGNORE. True = neu markiert, False = schon verarbeitet."""
    cur = conn.execute(
        "INSERT OR IGNORE INTO processed_events "
        "(event_id, processed_at) VALUES (?, ?)",
        (event_id, datetime.now(UTC).isoformat()),
    )
    conn.commit()
    return cur.rowcount == 1


def _unmark_processing(
    conn: sqlite3.Connection, event_id: str,
) -> None:
    """DELETE (kein Fehler, wenn fehlt)."""
    conn.execute(
        "DELETE FROM processed_events WHERE event_id = ?",
        (event_id,),
    )
    conn.commit()


# ---------------------------------------------------------------------- #
# Aufraeumen
# ---------------------------------------------------------------------- #

def _cleanup_old_events(conn: sqlite3.Connection) -> int:
    """
    Loescht processed_events-Eintraege, deren processed_at
    aelter ist als PROCESSED_EVENTS_MAX_AGE_DAYS. Rueckgabe:
    Anzahl geloeschter Zeilen. Kein VACUUM, kein Audit.
    """
    cutoff = (
        datetime.now(UTC)
        - timedelta(days=PROCESSED_EVENTS_MAX_AGE_DAYS)
    ).isoformat()
    cur = conn.execute(
        "DELETE FROM processed_events WHERE processed_at < ?",
        (cutoff,),
    )
    conn.commit()
    return cur.rowcount


# ---------------------------------------------------------------------- #
# run
# ---------------------------------------------------------------------- #

def run() -> int:
    """
    Ein Lauf. Exit-Codes siehe Modul-Docstring.

    Reihenfolge:
      1. Audit-Check (fail closed).
      2. DB-Connection + Schema-Check (fail closed).
      3. SecurityAI(skip_migrations=True) bauen.
      4. Cursor lesen, ggf. Tageswechsel.
      5. Neue Zeilen lesen.
      6. Pro Zeile: mark -> process -> Cursor-Update.
      7. close().
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    start = time.monotonic()

    # 1) Audit-Check (wie Dashboard)
    try:
        expected_owner = pwd.getpwuid(os.getuid()).pw_name
        check_audit_logs(_AUDIT_BASE_DIR, expected_owner)
    except AuditDirInconsistentError as exc:
        _log.error("audit-logs inkonsistent: %s", exc)
        return 1

    # 2) DB + Schema
    conn = connect(DEFAULT_DB_PATH)
    try:
        try:
            check_schema_version(conn, DEFAULT_MIGRATIONS_DIR)
        except SchemaVersionError as exc:
            _log.error("schema-version fehlgeschlagen: %s", exc)
            return 2

        # 3) SecurityAI (skip_migrations: Schema ist geprueft)
        ai: SecurityAI | None = None
        try:
            ai = SecurityAI(skip_migrations=True)

            # 4) Cursor + Tageswechsel
            cursor_file, cursor_offset = _read_cursor(conn)
            path = _current_events_path()
            today_name = path.name
            if cursor_file != today_name:
                cursor_offset = 0
                _write_cursor(conn, today_name, 0)

            # 5) Neue Zeilen
            try:
                lines = _read_new_lines(path, cursor_offset)
            except OSError as exc:
                _log.error("events-Datei nicht lesbar: %s", exc)
                return 4

            # 6) Pro Zeile
            processed = 0
            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    # Leere Zeile: Cursor trotzdem hochziehen.
                    _write_cursor(conn, today_name, cursor_offset + i + 1)
                    continue
                try:
                    data: dict[str, Any] = json.loads(line)
                    event = Event.from_dict(data)
                except (json.JSONDecodeError, KeyError, ValueError) as exc:
                    _log.error(
                        "event-Zeile %d unparsebar: %s",
                        cursor_offset + i + 1, exc,
                    )
                    # Cursor NICHT hochziehen: Zeile bleibt fuer
                    # den naechsten Lauf. Fail closed.
                    return 4

                if not _mark_processing(conn, event.event_id):
                    # Schon verarbeitet: skip, Cursor hochziehen.
                    _write_cursor(conn, today_name, cursor_offset + i + 1)
                    continue

                try:
                    ai.process(event)
                except Exception as exc:  # noqa: BLE001
                    _log.error(
                        "process fehlgeschlagen fuer %s: %s",
                        event.event_id, exc,
                    )
                    _unmark_processing(conn, event.event_id)
                    return 3

                _write_cursor(conn, today_name, cursor_offset + i + 1)
                processed += 1

            # 7) Aufraeumen (Buchhaltung, kein Audit).
            # Fehler beim Aufraeumen sind kein Lauf-Fehler
            # (Exit-Code bleibt 0), aber werden geloggt.
            try:
                removed = _cleanup_old_events(conn)
                if removed > 0:
                    _log.info(
                        "cleanup: %d old events removed",
                        removed,
                    )
            except Exception:  # noqa: BLE001
                _log.error("cleanup fehlgeschlagen")

            duration_ms = int((time.monotonic() - start) * 1000)
            _log.info(
                "reader_run events_read=%d events_processed=%d "
                "duration_ms=%d",
                len(lines), processed, duration_ms,
            )
            return 0
        finally:
            if ai is not None:
                try:
                    ai.close()
                except Exception as exc:  # noqa: BLE001
                    _log.error("ai.close() fehlgeschlagen: %s", exc)
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(run())
