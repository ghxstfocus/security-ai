-- Migration 0017: Permissions fuer Guardrails (Phase 5).
--
-- Zwei neue Permissions:
--   guardrail.view   -- Guardrails lesen
--   guardrail.manage -- Guardrails verwalten
--
-- Rollen-Zuordnung: admin bekommt beide.
-- Idempotent (INSERT OR IGNORE).
-- Voraussetzung: 0005_principals.sql (Rollen existieren).

INSERT OR IGNORE INTO permissions (code, description)
VALUES
    ('guardrail.view', 'Guardrails lesen'),
    ('guardrail.manage', 'Guardrails verwalten');

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'admin'
  AND p.code IN ('guardrail.view', 'guardrail.manage');