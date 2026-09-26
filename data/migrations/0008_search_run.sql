-- 0008_search_run.sql
-- search.run einfuegen.
-- admin + operator bekommen search.run.
-- viewer + system NICHT.
--
-- Voraussetzung: 0005_principals.sql wurde vorher
-- ausgefuehrt (Rollen admin/operator existieren).
-- apply_migrations sortiert lexikographisch,
-- 0005 laeuft also VOR 0008.
--
-- Idempotent: INSERT OR IGNORE + PRIMARY KEY
-- (role_id, permission_id).

INSERT OR IGNORE INTO permissions (code, description)
VALUES ('search.run', 'Globale Suche ausfuehren');

INSERT OR IGNORE INTO role_permissions
  (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'admin' AND p.code = 'search.run';

INSERT OR IGNORE INTO role_permissions
  (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'operator' AND p.code = 'search.run';
