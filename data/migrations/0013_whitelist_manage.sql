-- 0013_whitelist_manage.sql
-- Neue Permission whitelist.manage (Punkt 56a).
-- Rollen: admin + operator.
-- Zweck: Whitelist-Pflege im Dashboard.

INSERT OR IGNORE INTO permissions (code, description)
VALUES ('whitelist.manage', 'Whitelist pflegen (Punkt 56a)');

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name IN ('admin', 'operator')
  AND p.code = 'whitelist.manage';
