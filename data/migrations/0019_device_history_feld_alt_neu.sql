-- Migration 0019: device_history Spalten feld, alt, neu (OP-002b2).
--
-- OP-002b2 fordert eine Methode _insert_device_history, die vor dem
-- INSERT ein SELECT auf (device_id, feld, alt, neu, timestamp) macht.
-- Dafuer muessen die Spalten feld/alt/neu in device_history existieren.
-- Bestehende INSERTs (upsert_seen, record_offline, record_history)
-- bleiben unveraendert -- sie schreiben weiterhin in event_type und
-- data_json. Die neuen Spalten sind optional (nullable), damit alte
-- Eintraege und bestehende Code-Pfade unberuehrt bleiben.
--
-- Idempotent durch apply_migrations (schema_migrations-Tabelle).
-- Voraussetzung: 0002_inventory.sql (device_history existiert).

ALTER TABLE device_history ADD COLUMN feld TEXT;
ALTER TABLE device_history ADD COLUMN alt TEXT;
ALTER TABLE device_history ADD COLUMN neu TEXT;
