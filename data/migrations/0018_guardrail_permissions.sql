-- Migration 0018: Rollen-Zuordnungen fuer Guardrails (Phase 5).
--
-- WEG-Y-KORREKTUR (2026-10-16): die vorherige Nummer 0014 war
-- bereits belegt (0014_internal_name.sql). Naechste freie Nummer
-- ist 0018 (0017 ist U5).
--
-- Die Permissions guardrail.view und guardrail.manage wurden
-- bereits in 0017_guardrail_permissions.sql angelegt. Diese
-- Migration legt KEINE neuen Permissions an, sondern ergaenzt
-- nur die Rollen-Zuordnungen fuer operator und viewer.
--
-- Rollen-Zuordnung:
--   operator -> guardrail.view
--   viewer   -> guardrail.view
-- admin bekommt beide Permissions bereits in 0017.
--
-- Idempotent (INSERT OR IGNORE).
-- Voraussetzung: 0005_principals.sql (Rollen existieren),
--                0017_guardrail_permissions.sql (Permissions existieren).

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'operator'
  AND p.code = 'guardrail.view';

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'viewer'
  AND p.code = 'guardrail.view';