-- 0005_principals.sql
-- RBAC: Rollen, Permissions, Principals.
--
-- SQLite ist Quelle der Wahrheit.
--
-- Design:
-- - principals: alles, was authentifiziert werden kann.
--   kind: 'human' | 'system' | 'service'.
--   password_hash NULL fuer Systeme ohne Login.
-- - roles: benannte Rollen. role_permissions mappt Rollen auf
--   Permissions.
-- - permissions: feingranulare Codes (chat.ask, approval.decide, ...).
--
-- Passwort-Hashing (spaeter, Phase 3.6):
--   pbkdf2_sha256$600000$<salt_hex>$<hash_hex>
-- Phase 3.5 (Chat) laeuft ohne Login, cli-admin lokal.

CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
);

CREATE TABLE IF NOT EXISTS principals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL DEFAULT 'human',
    role_id INTEGER NOT NULL,
    password_hash TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE INDEX IF NOT EXISTS idx_principals_role ON principals(role_id);
CREATE INDEX IF NOT EXISTS idx_principals_kind ON principals(kind);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role
    ON role_permissions(role_id);

-- ------------------------------------------------------------------ --
-- Seed: Permissions
-- ------------------------------------------------------------------ --
INSERT OR IGNORE INTO permissions (code, description) VALUES
    ('chat.ask',              'Chat-Frage stellen'),
    ('chat.detail',           'Detail-Antworten anfordern'),
    ('chat.include_details',  'Rohdaten in Chat-Antwort einbeziehen'),
    ('device.read',           'Inventar lesen'),
    ('device.write',          'Inventar schreiben'),
    ('approval.view',         'Approvals anzeigen'),
    ('approval.decide',       'Approvals entscheiden'),
    ('change.view',           'Changes anzeigen'),
    ('change.create',         'Changes erstellen'),
    ('change.decide',         'Changes freigeben/ablehnen'),
    ('change.deploy',         'Changes deployen'),
    ('audit.read',            'Audit-Log lesen'),
    ('audit.write',           'Audit-Log schreiben'),
    ('principal.manage',      'Principals verwalten'),
    ('role.manage',           'Rollen verwalten');

-- ------------------------------------------------------------------ --
-- Seed: Rollen
-- ------------------------------------------------------------------ --
INSERT OR IGNORE INTO roles (name, description, created_at) VALUES
    ('admin',    'Vollzugriff',                    '2026-01-01T00:00:00+00:00'),
    ('operator', 'Betrieb: Approvals, Changes',    '2026-01-01T00:00:00+00:00'),
    ('viewer',   'Nur lesen',                      '2026-01-01T00:00:00+00:00'),
    ('system',   'Interne Komponente, kein Login', '2026-01-01T00:00:00+00:00');

-- ------------------------------------------------------------------ --
-- Seed: role_permissions
-- ------------------------------------------------------------------ --

-- admin: alle Permissions
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = 'admin';

-- operator
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'operator' AND p.code IN (
    'chat.ask', 'chat.detail', 'chat.include_details',
    'device.read',
    'approval.view', 'approval.decide',
    'change.view', 'change.create', 'change.decide',
    'audit.read'
);

-- viewer
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'viewer' AND p.code IN (
    'chat.ask', 'device.read', 'audit.read'
);

-- system
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'system' AND p.code IN (
    'chat.ask', 'device.read', 'audit.write'
);
