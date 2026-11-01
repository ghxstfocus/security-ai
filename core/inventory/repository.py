# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
DB-Zugriff fuer das Inventory.

- connect()             : oeffnet SQLite, PRAGMA foreign_keys = ON
- apply_migrations()    : spielt data/migrations/*.sql sortiert ein
- DeviceRepository      : CRUD auf devices und device_history

Zeitstempel werden als ISO-8601-Strings gespeichert (SQLite hat kein
echtes DATETIME). Das Modell Device arbeitet mit datetime (UTC).
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.inventory.device import Device, normalize_ip
from core.sentinels import FALLBACK_SENTINEL

# Single source of truth fuer den DB-Pfad.
# Kann spaeter nach core/config.py wandern, wenn mehr
# Einstellungen dazukommen (Log-Level, Telegram,
# Netzwerk-Scope, Scan-Schwellen).
DEFAULT_DB_PATH = Path("data/inventory.db")

# Sentinel-Wert aus dem Fritz!Box-Watcher (Punkt 67a, Auflage 1765).
# Bedeutung: der neue entity_name ist ein Fallback, kein echter Name.
# Das Repository setzt dann entity_name auf None statt zu ueberschreiben.
DEFAULT_MIGRATIONS_DIR = Path("data/migrations")

logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def connect(db_path: Path | str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Oeffnet eine SQLite-Verbindung mit Row-Factory und FK-Constraints."""
    path = Path(db_path)
    if path != Path(":memory:"):
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


_MIGRATION_VERSION_RE = re.compile(r"^(\d{4})_")


def ensure_schema_migrations(conn: sqlite3.Connection) -> None:
    """
    Legt die Tracking-Tabelle an, falls sie fehlt.

    Eine Quelle der Wahrheit fuer das Schema dieser Tabelle.
    0002_inventory.sql legt sie ebenfalls an (IF NOT EXISTS),
    das ist idempotent und schadet nicht. Aenderungen am
    Tracking-Schema gehoeren HIERHIN, nicht in 0002.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "    version     INTEGER PRIMARY KEY,"
        "    applied_at  TEXT NOT NULL"
        ")"
    )


def _parse_migration_version(filename: str) -> int | None:
    """
    Liest die vierstellige Versionsnummer aus dem Dateinamen.

    Strikt: genau vier Ziffern, dann Unterstrich.
    "0003_approvals.sql" -> 3
    "0000_init.sql"      -> 0
    "10000_x.sql"        -> None (fuenfstellig, wird uebersprungen)
    "init.sql"           -> None (kein Praefix, wird uebersprungen)
    """
    m = _MIGRATION_VERSION_RE.match(filename)
    if m is None:
        return None
    return int(m.group(1))


class InventoryRepositoryError(RuntimeError):
    """Basis fuer Inventory-Repository-Fehler."""


class SchemaVersionError(RuntimeError):
    """Die DB-Schema-Version passt nicht zu den vorhandenen Migrationen."""


def _highest_file_version(
    migrations_dir: Path | str,
) -> int | None:
    """
    Hoechste vierstellige Version in migrations_dir/*.sql.
    None, wenn keine passende Datei existiert.
    """
    d = Path(migrations_dir)
    if not d.exists():
        return None
    versions: list[int] = []
    for f in d.glob("*.sql"):
        v = _parse_migration_version(f.name)
        if v is not None:
            versions.append(v)
    return max(versions) if versions else None


def check_schema_version(
    conn: sqlite3.Connection,
    migrations_dir: Path | str = DEFAULT_MIGRATIONS_DIR,
) -> None:
    """
    Prueft, ob die DB-Schema-Version zur hoechsten
    Migrationsdatei passt.

    - DB < Datei : SchemaVersionError (fail closed).
    - DB > Datei : logger.warning, kein raise (Downgrade).
    - DB == Datei: still.
    - Tabelle schema_migrations fehlt : SchemaVersionError
      mit diagnostischer Meldung (Auflage 403).
    - Kein Datei-Praefix und DB 0 : still (Auflage 404).
    """
    try:
        row = conn.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            raise SchemaVersionError(
                "schema_migrations fehlt. Migrationen wurden "
                "nicht angewandt. Deploy-Schritt "
                "(DEPLOYMENT 3e) pruefen."
            ) from exc
        raise

    db_v = int(row[0]) if row and row[0] is not None else 0
    file_v = _highest_file_version(migrations_dir)
    if file_v is None:
        file_v = 0

    if db_v < file_v:
        raise SchemaVersionError(
            f"DB-Schema-Version {db_v:04d} ist kleiner als "
            f"hoechste Migration {file_v:04d}. "
            "Migrationen fehlen. Deploy-Schritt "
            "(DEPLOYMENT 3e) pruefen."
        )
    if db_v > file_v:
        logger.warning(
            "DB-Schema-Version %04d ist groesser als hoechste "
            "Migration %04d. Downgrade erkannt.",
            db_v, file_v,
        )


def apply_migrations(
    conn: sqlite3.Connection,
    migrations_dir: Path | str = DEFAULT_MIGRATIONS_DIR,
) -> list[str]:
    """
    Spielt alle *.sql-Dateien im Verzeichnis sortiert ein.

    Idempotent auf zwei Ebenen:
      1. Skip: Dateien, deren Version bereits in
         schema_migrations steht, werden uebersprungen.
      2. SQL: die Migrationen selbst nutzen IF NOT EXISTS
         und INSERT OR IGNORE.

    Dateinamen ohne strikt vierstellige Version (z.B. "init.sql"
    oder "10000_x.sql") werden uebersprungen und gemeldet.
    Nur *.sql wird verarbeitet.

    Rueckgabe: Liste der in DIESEM Lauf angewendeten Dateinamen.
    Uebersprungene Dateien werden per print() gemeldet (Auflage 394).
    """
    d = Path(migrations_dir)
    if not d.exists():
        raise FileNotFoundError(f"Migrationsverzeichnis fehlt: {d}")

    ensure_schema_migrations(conn)

    done_rows = conn.execute(
        "SELECT version FROM schema_migrations"
    ).fetchall()
    done: set[int] = {int(r[0]) for r in done_rows}

    applied: list[str] = []
    for sql_file in sorted(d.glob("*.sql")):
        version = _parse_migration_version(sql_file.name)
        if version is None:
            print(f"uebersprungen (kein vierstelliges Versionspraefix): "
                  f"{sql_file.name}")
            continue
        if version in done:
            print(f"uebersprungen (bereits angewandt): {sql_file.name}")
            continue

        sql = sql_file.read_text(encoding="utf-8")
        conn.executescript(sql)
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations (version, applied_at) "
            "VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            (version,),
        )
        done.add(version)
        applied.append(sql_file.name)

    conn.commit()
    return applied


class DeviceRepository:
    """CRUD fuer devices und device_history."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # ------------------------------------------------------------------ #
    # Lesen
    # ------------------------------------------------------------------ #

    def get(self, identifier: str) -> Device | None:
        row = self._conn.execute(
            "SELECT id, identifier, entity_name, network_type, "
            "       first_seen, last_seen, notes, last_ip, "
            "       internal_name "
            "FROM devices WHERE identifier = ?",
            (identifier,),
        ).fetchone()
        if row is None:
            return None
        return Device.from_row(row)

    def list_all(self) -> list[Device]:
        rows = self._conn.execute(
            "SELECT id, identifier, entity_name, network_type, "
            "       first_seen, last_seen, notes, last_ip, "
            "       internal_name "
            "FROM devices ORDER BY last_seen DESC"
        ).fetchall()
        return [Device.from_row(r) for r in rows]

    def count_by_network(self) -> dict[str, int]:
        """Geraete-Anzahl pro network_type (T3, Auflage 1689).

        Rueckgabe: alle drei bekannten Keys, 0 bei fehlend.
        Unbekannte network_type-Werte werden nicht gezaehlt.
        """
        out: dict[str, int] = {
            "Hauptnetz": 0,
            "Gastnetz": 0,
            "Extern": 0,
        }
        rows = self._conn.execute(
            "SELECT network_type, COUNT(*) AS n "
            "FROM devices "
            "WHERE network_type IN "
            "('Hauptnetz', 'Gastnetz', 'Extern') "
            "GROUP BY network_type"
        ).fetchall()
        for r in rows:
            out[r["network_type"]] = int(r["n"])
        return out

    def history(self, identifier: str, limit: int = 100) -> list[dict[str, Any]]:
        row = self._conn.execute(
            "SELECT id FROM devices WHERE identifier = ?",
            (identifier,),
        ).fetchone()
        if row is None:
            return []
        rows = self._conn.execute(
            "SELECT id, device_id, timestamp, event_type, network_type, data_json "
            "FROM device_history WHERE device_id = ? "
            "ORDER BY timestamp DESC LIMIT ?",
            (row["id"], limit),
        ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append({
                "id": r["id"],
                "device_id": r["device_id"],
                "timestamp": r["timestamp"],
                "event_type": r["event_type"],
                "network_type": r["network_type"],
                "data": json.loads(r["data_json"] or "{}"),
            })
        return out

    # ------------------------------------------------------------------ #
    # Schreiben
    # ------------------------------------------------------------------ #

    def upsert_seen(
        self,
        identifier: str,
        *,
        entity_name: str | None = None,
        network_type: str | None = None,
        event_type: str = "device_seen",
        data: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
        ip: str | None = None,
    ) -> Device:
        """
        Legt das Geraet an oder aktualisiert last_seen.

        Schreibt immer einen History-Eintrag (event_type default
        "device_seen"). entity_name/network_type/last_ip werden
        nur ueberschrieben, wenn sie einen Wert tragen — so
        verliert ein Update nichts.

        last_ip: None und "" gelten beide als "keine IP".
        Auflage 1757, Punkt 67b.

        entity_name: FALLBACK_SENTINEL bedeutet "kein
        echter Name" und wird als None gespeichert
        (INSERT und UPDATE, Auflage 1771, Punkt 67a).

        internal_name ist Nutzer-Eigentum (Punkt 75) und
        wird von upsert_seen NICHT angefasst (weder INSERT
        noch UPDATE). Watcher-Events duerfen den Namen
        nicht ueberschreiben.
        """
        ts = (timestamp or datetime.now(UTC)).isoformat()
        data_json = json.dumps(data or {}, ensure_ascii=False, sort_keys=True)

        # Vorab-SELECT: alt-Zustand (id + last_ip) VOR jedem Update merken.
        pre = self._conn.execute(
            "SELECT id, last_ip FROM devices WHERE identifier = ?",
            (identifier,),
        ).fetchone()

        if pre is None:
            insert_name = (
                None if entity_name == FALLBACK_SENTINEL else entity_name
            )
            self._conn.execute(
                "INSERT INTO devices "
                "(identifier, entity_name, network_type, first_seen, last_seen, notes, last_ip) "
                "VALUES (?, ?, ?, ?, ?, NULL, ?)",
                (identifier, insert_name, network_type, ts, ts, ip),
            )
            self._conn.commit()
            result = self.get(identifier)
            if result is None:
                raise InventoryRepositoryError(
                    f"Device {identifier!r} nach INSERT nicht gefunden"
                )
            return result

        device_id = int(pre["id"])
        alt_ip = pre["last_ip"]

        existing = self.get(identifier)
        if existing is None:
            raise InventoryRepositoryError(
                f"Device {identifier!r} nach SELECT nicht gefunden"
            )
        if entity_name == FALLBACK_SENTINEL:
            new_name = None
        elif entity_name is not None:
            new_name = entity_name
        else:
            new_name = existing.entity_name
        new_net = (
            network_type if network_type is not None else existing.network_type
        )
        try:
            self._conn.execute(
                "UPDATE devices SET entity_name = ?, network_type = ?, "
                "last_seen = ? WHERE id = ?",
                (new_name, new_net, ts, device_id),
            )
            changed = self.update_last_ip_if_changed(
                identifier, ip, commit=False,
            )
            if changed:
                neu = normalize_ip(ip)
                if neu is None:
                    neu = ip.strip() if isinstance(ip, str) else ip
                self._insert_device_history(
                    device_id,
                    feld="last_ip",
                    alt=alt_ip,
                    neu=neu,
                    timestamp=ts,
                )
            self._conn.execute(
                "INSERT INTO device_history "
                "(device_id, timestamp, event_type, network_type, data_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (device_id, ts, event_type, network_type, data_json),
            )
        except sqlite3.Error:
            self._conn.rollback()
            raise

        self._conn.commit()

        result = self.get(identifier)
        if result is None:
            raise InventoryRepositoryError(
                f"Device {identifier!r} nach UPDATE nicht gefunden"
            )
        return result

    def mark_offline(
        self,
        identifier: str,
        *,
        data: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> bool:
        """
        Traegt ein device_offline-Event in die History ein.

        last_seen wird NICHT aktualisiert (das Geraet ist ja weg).
        Rueckgabe: True, wenn das Geraet existiert.
        """
        row = self._conn.execute(
            "SELECT id, network_type FROM devices WHERE identifier = ?",
            (identifier,),
        ).fetchone()
        if row is None:
            return False

        ts = (timestamp or datetime.now(UTC)).isoformat()
        data_json = json.dumps(data or {}, ensure_ascii=False, sort_keys=True)
        self._conn.execute(
            "INSERT INTO device_history "
            "(device_id, timestamp, event_type, network_type, data_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (row["id"], ts, "device_offline", row["network_type"], data_json),
        )
        self._conn.commit()
        return True

    def set_internal_name(
        self, identifier: str, name: str | None,
    ) -> None:
        """Setzt internal_name (Punkt 75). None loescht den Wert.

        Nur der Nutzerpfad. upsert_seen fasst das Feld nicht an.
        """
        self._conn.execute(
            "UPDATE devices SET internal_name = ? "
            "WHERE identifier = ?",
            (name, identifier),
        )
        self._conn.commit()

    def record_history(
        self,
        identifier: str,
        event_type: str,
        *,
        network_type: str | None = None,
        data: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> bool:
        """
        Generischer History-Eintrag (z.B. "whitelist_added").

        Rueckgabe: True, wenn das Geraet existiert.
        """
        row = self._conn.execute(
            "SELECT id FROM devices WHERE identifier = ?",
            (identifier,),
        ).fetchone()
        if row is None:
            return False
        ts = (timestamp or datetime.now(UTC)).isoformat()
        data_json = json.dumps(data or {}, ensure_ascii=False, sort_keys=True)
        self._conn.execute(
            "INSERT INTO device_history "
            "(device_id, timestamp, event_type, network_type, data_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (row["id"], ts, event_type, network_type, data_json),
        )
        self._conn.commit()
        return True

    def _insert_device_history(
        self,
        device_id: int,
        feld: str,
        alt: str | None,
        neu: str | None,
        timestamp: str,
    ) -> bool:
        """Fuegt einen field_change-Eintrag in device_history ein.

        Duplikat-Check per NULL-sicherem IS-Vergleich auf feld/alt/neu.
        Committet NICHT — Transaktionshoheit liegt beim Aufrufer.
        """
        if not isinstance(device_id, int) or device_id <= 0:
            raise ValueError("device_id muss eine positive Ganzzahl sein")
        if not isinstance(feld, str) or not feld.strip():
            raise ValueError("feld muss ein nicht-leerer String sein")
        if not isinstance(timestamp, str) or not timestamp:
            raise ValueError(
                "timestamp muss ein nicht-leerer ISO-8601-String sein"
            )

        existing = self._conn.execute(
            "SELECT 1 FROM device_history "
            "WHERE device_id = ? AND feld IS ? AND alt IS ? "
            "AND neu IS ? AND timestamp = ?",
            (device_id, feld, alt, neu, timestamp),
        ).fetchone()
        if existing is not None:
            logger.debug(
                "device_history-Duplikat uebersprungen: device_id=%s feld=%s",
                device_id, feld,
            )
            return False

        self._conn.execute(
            "INSERT INTO device_history "
            "(device_id, timestamp, event_type, network_type, data_json, "
            " feld, alt, neu) "
            "VALUES (?, ?, 'field_change', NULL, '{}', ?, ?, ?)",
            (device_id, timestamp, feld, alt, neu),
        )
        return True

    def update_last_ip_if_changed(
        self, identifier: str, ip: str | None, *, commit: bool = True,
    ) -> bool:
        """Aktualisiert last_ip nur bei echter Aenderung.

        Rueckgabe: True, wenn ein UPDATE ausgefuehrt wurde,
        False wenn der Identifier unbekannt ist oder der
        normalisierte Wert unveraendert ist.

        commit=False: die Transaktion bleibt offen und gehoert
        dem Aufrufer (Transaktionshoheit beim Aufrufer).
        """
        if not ip:
            return False
        ziel = normalize_ip(ip)
        # OP-002b1-Fix: ip="" oder ip=None = "kein Diff". Sonst wuerde
        # UPDATE last_ip auf None setzen, was der alte Code durch
        # "new_ip = ip if ip else existing.last_ip" verhinderte.
        if ziel is None:
            return False
        row = self._conn.execute(
            "SELECT id, last_ip FROM devices WHERE identifier = ?",
            (identifier,),
        ).fetchone()
        if row is None:
            return False
        alt = normalize_ip(row["last_ip"])
        if alt == ziel:
            return False
        self._conn.execute(
            "UPDATE devices SET last_ip = ? WHERE identifier = ?",
            (ziel, identifier),
        )
        if commit:
            self._conn.commit()
        return True

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]


__all__ = [
    "DEFAULT_DB_PATH",
    "DEFAULT_MIGRATIONS_DIR",
    "DeviceRepository",
    "InventoryRepositoryError",
    "SchemaVersionError",
    "apply_migrations",
    "check_schema_version",
    "connect",
]
