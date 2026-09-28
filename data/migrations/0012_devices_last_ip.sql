-- 0012_devices_last_ip.sql
-- Kontext-Feld: zuletzt gesehene IP-Adresse eines Geraets.
-- Nicht die Identitaet (das ist identifier / MAC).
-- DHCP kann die IP aendern -> last_ip ist Momentaufnahme.
-- Kein Index, kein UNIQUE, kein NOT NULL (Alt-Eintraege = NULL).

ALTER TABLE devices ADD COLUMN last_ip TEXT;
