-- Migration 0002: Inventory (devices, device_history, whitelisted_devices).
--
-- Eine Quelle der Wahrheit:
--   devices              = was wir gesehen haben (Zustand pro Identifier)
--   device_history       = append-only Ereignisse pro Geraet
--   whitelisted_devices  = was der Mensch explizit erlaubt hat
--
-- Die Whitelist ist NICHT Teil von devices. Wer auf der Whitelist steht,
-- wird ausschliesslich ueber whitelisted_devices.identifier geprueft.
--
-- device_history.event_type ist bewusst frei (kein CHECK). Konvention:
--   "device_seen", "device_offline", "whitelist_added", "whitelist_removed"
-- data_json traegt die Details (freies JSON, schema-los erweiterbar).
--
-- Erweiterbar fuer Stufe 5 (Personen, Raeume, Zutritte):
--   - alle PKs sind INTEGER AUTOINCREMENT
--   - device_id ist ein echter Foreign Key
--   - neue Tabellen (persons, rooms, access_events) koennen daneben
--     entstehen, ohne devices/device_history anzufassen.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS, CREATE INDEX IF NOT EXISTS.
-- Kein DROP. PRAGMA foreign_keys wird pro Verbindung im Repository gesetzt.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier    TEXT    NOT NULL UNIQUE,
    entity_name   TEXT,
    network_type  TEXT,
    first_seen    TEXT    NOT NULL,
    last_seen     TEXT    NOT NULL,
    notes         TEXT
);

CREATE INDEX IF NOT EXISTS idx_devices_network_type
    ON devices (network_type);

CREATE INDEX IF NOT EXISTS idx_devices_last_seen
    ON devices (last_seen);

CREATE TABLE IF NOT EXISTS device_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     INTEGER NOT NULL,
    timestamp     TEXT    NOT NULL,
    event_type    TEXT    NOT NULL,
    network_type  TEXT,
    data_json     TEXT    NOT NULL DEFAULT '{}',
    FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_device_history_device_ts
    ON device_history (device_id, timestamp);

CREATE INDEX IF NOT EXISTS idx_device_history_event_type
    ON device_history (event_type);

CREATE TABLE IF NOT EXISTS whitelisted_devices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    identifier   TEXT    NOT NULL UNIQUE,
    entity_name  TEXT    NOT NULL,
    added_by     TEXT,
    notes        TEXT
);

CREATE INDEX IF NOT EXISTS idx_whitelisted_devices_identifier
    ON whitelisted_devices (identifier);

INSERT OR IGNORE INTO schema_migrations (version, applied_at)
    VALUES (2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
