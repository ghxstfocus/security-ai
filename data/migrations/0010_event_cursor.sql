-- 0010_event_cursor.sql
-- Cursor fuer den Event-Reader (Punkt 26, Phase 3.8a).
-- Eine Zeile pro Reader. Heute nur ein Reader (Orchestrator).
-- file_name wechselt mit dem Tag (data/events-YYYY-MM-DD.jsonl),
-- line_offset ist die Anzahl bereits gelesener Zeilen.

CREATE TABLE IF NOT EXISTS event_cursor (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    file_name TEXT NOT NULL,
    line_offset INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

INSERT OR IGNORE INTO event_cursor
    (id, file_name, line_offset, updated_at)
    VALUES (1, '', 0, '1970-01-01T00:00:00+00:00');
