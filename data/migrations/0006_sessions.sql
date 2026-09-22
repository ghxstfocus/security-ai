-- 0006_sessions.sql
-- Serverseitige Sessions und Login-Versuche.
--
-- Design:
-- - sessions: eine Zeile pro aktiver Session. Cookie traegt
--   nur die session_id (id). Kein Nutzdaten-Cookie.
-- - login_attempts: fuer Rate-Limit auf /login (pro IP).
--   Wird nicht fuer RBAC genutzt, nur fuer Limit.
-- - Idempotent: CREATE TABLE IF NOT EXISTS.
--
-- Aufraeumen (Phase 3.6.15, nicht hier):
--   - sessions mit revoked_at IS NOT NULL oder
--     last_seen_at < now - 30 Tage
--   - login_attempts mit attempted_at < now - 30 Tage
--
-- Hinweis: FK ist AKTIV, weil connect() PRAGMA
-- foreign_keys = ON setzt. Ein INSERT mit unbekanntem
-- principal_name schlaegt mit IntegrityError fehl.
-- RBAC prueft principal_name zusaetzlich serverseitig
-- (Defense in Depth).

CREATE TABLE IF NOT EXISTS sessions (
    id             TEXT PRIMARY KEY,
    principal_name TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL,
    revoked_at     TEXT,
    ip             TEXT,
    user_agent     TEXT,
    FOREIGN KEY (principal_name) REFERENCES principals(name)
);

CREATE INDEX IF NOT EXISTS idx_sessions_principal
    ON sessions(principal_name);
CREATE INDEX IF NOT EXISTS idx_sessions_revoked
    ON sessions(revoked_at);

CREATE TABLE IF NOT EXISTS login_attempts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ip             TEXT NOT NULL,
    principal_name TEXT,
    attempted_at   TEXT NOT NULL,
    success        INTEGER NOT NULL  -- 0/1, wie principals.is_active
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
    ON login_attempts(ip, attempted_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_principal_time
    ON login_attempts(principal_name, attempted_at);
