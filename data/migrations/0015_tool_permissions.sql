-- 0015_tool_permissions.sql
-- Drei neue Permissions fuer Punkt 58 Runde 1.
-- admin: alle drei. operator: net_diag + sys_status.
-- viewer + system: keine.
--
-- Idempotent: INSERT OR IGNORE + PRIMARY KEY (role_id, permission_id).
-- Voraussetzung: 0005_principals.sql ist gelaufen (Rollen existieren).

INSERT OR IGNORE INTO permissions (code, description) VALUES
    ('tool.net_diag', 'Netzwerk-Diagnose-Tools'),
    ('tool.sys_status', 'System-Status-Tools'),
    ('tool.db_read', 'Datenbank-Lese-Tools');

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'admin'
  AND p.code IN ('tool.net_diag', 'tool.sys_status', 'tool.db_read');

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'operator'
  AND p.code IN ('tool.net_diag', 'tool.sys_status');
