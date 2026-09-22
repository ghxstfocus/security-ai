-- 0007_alert_permission.sql
-- alert.view einfuegen.
-- admin + operator bekommen alert.view.
-- viewer + system NICHT.
--
-- Voraussetzung: 0005_principals.sql wurde vorher
-- ausgefuehrt (Rollen admin/operator existieren).
-- apply_migrations sortiert lexikographisch,
-- 0005 laeuft also VOR 0007.
--
-- Idempotent: INSERT OR IGNORE + PRIMARY KEY
-- (role_id, permission_id).

INSERT OR IGNORE INTO permissions (code, description)
VALUES ('alert.view', 'Alarme anzeigen');

INSERT OR IGNORE INTO role_permissions
  (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'admin' AND p.code = 'alert.view';

INSERT OR IGNORE INTO role_permissions
  (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'operator' AND p.code = 'alert.view';
