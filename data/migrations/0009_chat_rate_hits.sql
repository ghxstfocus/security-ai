-- 0009_chat_rate_hits.sql
-- Rate-Limit fuer /api/chat, Multi-Worker-fest.
--
-- Design:
-- - Eine Zeile pro erlaubter Anfrage.
-- - principal_name: Schluessel (wie bisher).
-- - hit_at: ISO-8601 UTC.
-- - Haushaltung im Service: alte Zeilen werden bei
--   jedem allow()-Aufruf geloescht.
-- - Kein Audit, kein Log.
-- - Kein CHECK auf Spalten (Konvention im Code).
--
-- Index auf (principal_name, hit_at) fuer die
-- Zaehlung und das Loeschen.

CREATE TABLE IF NOT EXISTS chat_rate_hits (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    principal_name TEXT NOT NULL,
    hit_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chat_rate_hits_principal
    ON chat_rate_hits (principal_name, hit_at);

INSERT OR IGNORE INTO schema_migrations (version, applied_at)
    VALUES (9, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
