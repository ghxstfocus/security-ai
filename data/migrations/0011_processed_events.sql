-- 0011_processed_events.sql
-- Idempotenz-Marker fuer den Event-Reader (Punkt 26, Phase 3.8b).
-- Eine Zeile pro verarbeitetem Event (event_id = PRIMARY KEY).
-- Verhindert doppelte Verarbeitung bei Fehler + Retry.
-- Kein FK (Event lebt nicht in der DB).

CREATE TABLE IF NOT EXISTS processed_events (
    event_id TEXT PRIMARY KEY,
    processed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_processed_events_processed_at
    ON processed_events (processed_at);
