-- 0014_internal_name.sql
-- Nutzervergebener interner Name fuer ein Geraet (Punkt 75).
-- Nicht die Identitaet (identifier / MAC) und nicht der
-- Fritz!Box-Name (entity_name). last_ip bleibt Kontext.
-- Der Watcher schreibt internal_name nie.

ALTER TABLE devices ADD COLUMN internal_name TEXT;
