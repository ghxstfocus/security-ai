# ADR-0005: Wichtige Konventionen

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §5

---

## 5. Wichtige Konventionen

### Pfade

- DEFAULT_DB_PATH = data/inventory.db
  (in core/inventory/repository.py, wandert spaeter nach
  core/config.py wenn mehr Einstellungen dazukommen)
- DEFAULT_MIGRATIONS_DIR = data/migrations
- detection/rules.yaml (Detection-Config)
- core/risk/rules.yaml (Risk-Config)
- policies/tools.yaml (Policy)
- apps/security_ai/config.yaml (Orchestrator-Config)
- audit-logs/ (JSONL-Audit)

### Zeitstempel

Immer timezone-aware (UTC). ISO-8601-Strings in JSONL/DB.
Naive datetime wird abgelehnt (Fail closed).

### Events sind unveraenderlich

Event ist frozen. Aenderungen erzeugen ein neues Event
(core/events/event.py::with_data).

### identifier in devices/whitelisted_devices

identifier ist TEXT. Kein Format-Check, kein
Schema-Zwang. MAC bevorzugt (stabil ueber DHCP-
Wechsel). Fallback IP, wenn keine MAC verfuegbar
(z. B. nmap ohne Root).

Der Fritz!Box-Watcher (Phase 3.8a) liefert MACs.
Der nmap-Parser liefert weiterhin nur IP (kein
identifier). Beide Werte sind gueltig.

MAC-Randomisierung (iOS/Android/Windows) ist
offener Punkt 43 in SECURITY_REVIEW_LOG.

### Event-Transport (Phase 3.8a)

Fritz!Box-Watcher (Producer) schreibt Events als JSONL
nach data/events-YYYY-MM-DD.jsonl (UTC-Datum,
append-only, eine JSON-Zeile pro Event via Event.to_json).
Der Orchestrator (Punkt 26) liest neue Zeilen und merkt
sich Datei + Offset in der DB-Tabelle event_cursor
(Migration 0010). Kein Datei-Cursor.

Der Watcher-Zustand (letzter Host-Stand) liegt dagegen
in data/fritzbox_state.json (Datei, nicht DB). Grund:
klein, kein Query-Bedarf, single Prozess.

Der State traegt normalisierte Werte: Fallback-
Namen der Fritz!Box (PC-<MAC>, PC-<IP>) werden
als Sentinel `__FALLBACK__` gespeichert, nicht
in der Rohform. Grund: der State ist die Diff-
Basis des Watchers (Was hat der Watcher beim
letzten Lauf gesehen?), kein Roh-Spiegel der
Fritz!Box. Der relevante Diff fuer spaetere
Events ist "Fallback -> echter Name"; ein
Fallback-zu-Fallback-Wechsel ist praktisch
ausgeschlossen (MAC stabil). Punkt 67a,
Auflagen 1773-1774.

Audit: ein watcher_run-Eintrag pro Lauf mit Events,
kein Audit bei 0 Events und kein Audit bei Fehler-Exit.

### processed_events und event_cursor (Phase 3.8b)

Zwei Tabellen in der DB (beide Migrations):

- event_cursor (Migration 0010): eine Zeile (id=1) mit
  file_name + line_offset. Fortschritt des Event-Readers.
  Tageswechsel: file_name aendert sich, line_offset 0.
- processed_events (Migration 0011): event_id PRIMARY KEY,
  processed_at. Idempotenz-Marker.

Der Reader (tools/event_reader.py) nutzt beide:
1. INSERT OR IGNORE INTO processed_events (event_id).
2. rowcount == 0 -> skip.
3. SecurityAI.process(event).
4. Bei Erfolg: Cursor +1.
5. Bei Fehler: DELETE FROM processed_events.
   Cursor bleibt, naechster Lauf versucht es erneut.

Grund: SecurityAI.process() ist NICHT idempotent
(AgentLoop kann Tools ausloesen, Audit ist append-only).
Ohne Marker wuerde ein Fehler zu doppelten Alarmen fuehren.

### last_ip in devices (Punkt 48)

devices.last_ip TEXT (Migration 0012, nullable).

- Kontext-Feld: zuletzt gesehene IP-Adresse.
- KEIN Identitaets-Feld: identifier (MAC) bleibt
  die Identitaet. DHCP kann die IP jederzeit
  aendern.
- Kein Index, kein UNIQUE, kein NOT NULL.
- upsert_seen(..., ip=None): INSERT schreibt
  last_ip; UPDATE ueberschreibt nur, wenn ip nicht
  None (Muster wie entity_name/network_type).
- Detailseite zeigt last_ip (Fallback "—").
  Liste bleibt kompakt.
