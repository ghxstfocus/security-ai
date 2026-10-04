# Design-Entscheidungen

> Dieses Dokument sammelt die verbindlichen Entscheidungen, die
> im Verlauf des Projekts getroffen wurden. Es ist die erste
> Adresse bei Unklarheiten.
>
> Stand: 2026-10-02 (HEAD 413540e),
> mypy 0, ruff 0, Tests 1191.
> Erledigt: Punkte 55, 56a, 65, 66, 67 (a/b),
> 68, 70, 71, 72, 73, 73a, 74, 75, 77, 79, 79a.
> Offen: 56 (Dashboard-Aktionen),
> 57 (Guardrails), 58 (Werkzeuge-Werkbank),
> 76 (Telegram, optional), 80 (Alarme-Filter),
> 34, 43, 49, 53b, 54.

---

## 1. Design-Entscheidungen

### 1. Input-/Output-Event-Typen strikt getrennt

- connection_attempt / syn_packet -> PORT_SCAN
- device_presence / device_offline -> UNKNOWN_DEVICE

Keine Regel triggert auf ihr eigenes Output-Event.

Begruendung: Sonst Endlosschleifen und unklare Verantwortung.

### 2. State im RuleContext, nicht im Regel-Objekt

Regeln sind zustandslos. Zustand (Ringpuffer fuer port_scan)
liegt in RuleContext.state, thread-sicher und resetbar.

Begruendung: Spaetere Auslagerung in Redis/DB moeglich, ohne
Regeln anzufassen. Keine Multi-Threading-Probleme.

### 3. DB nur im Orchestrator

Detection und Risk sind DB-frei. Der Orchestrator liest
Snapshots und reicht sie als Kontext durch.

Begruendung: Determinismus, Testbarkeit, klare Verantwortung.

### 4. Inventory-Update VOR Detection/Risk

Ein device_presence-Event wird erst ins Inventory geschrieben,
dann durch Detection/Risk bewertet.

Der not_in_inventory-Bonus greift NICHT beim allerersten
Auftreten. Stattdessen setzt der Orchestrator
first_seen=True/False in den Alert (Pre-Snapshot-Vergleich),
und der Risk-Pruefer first_seen greift darauf.

Begruendung: Risk Engine sieht aktuellen Zustand. Ein frisch
angelegtes Geraet ist "in_inventory", aber nicht "known".

### 5. Append-only History

device_history.event_type ist frei (kein CHECK). Konventionen:
- device_seen
- device_offline
- whitelist_added
- whitelist_removed

data_json ist schema-los (freies JSON).

Begruendung: Neue Event-Typen ohne Migration. Die Konvention
steht im Code, nicht in der DB.

### 6. Whitelist als eigene Tabelle

whitelisted_devices ist die einzige Quelle fuer "wer ist
erlaubt". Kein is_whitelisted-Feld in devices.

Begruendung: Zwei Quellen der Wahrheit fuehren zu Bugs.

### 7. Risk Engine deterministisch, kein LLM

base + add-Modifier, auditierbar. Kein Multiplikator, keine
Konditional-Logik (fuer jetzt).

Begruendung: Scores muessen reproduzierbar und nachvollziehbar
sein. Das LLM erklaert spaeter nur.

### 8. Fail closed

- Unbekannter when-Name -> RiskRuleError
- Fehlender default-Block in rules.yaml -> RiskRuleError
- Fehlende Predicate-Felder -> False (fail safe)

Begruendung: Kein stiller Durchlauf bei Konfigurationsfehlern.

### 9. Alert-Events erben event.timestamp

Der Alert beschreibt das Ereignis, nicht den Erkennungszeitpunkt.
RiskAssessment.timestamp = Bewertungszeitpunkt.

Begruendung: Risk Engine prueft nachts/wochenende gegen den
Vorfall, nicht gegen jetzt.

### 10. Frischer Inventory-Snapshot pro process()-Call

Alle Alerts eines Events sehen denselben Zustand. Nicht pro
Alert ein eigener Snapshot.

Begruendung: Determinismus pro Verarbeitungsschritt.

### 11. base + add ohne Multiplikatoren

Reicht fuer Phase 2b. rules.yaml-Schema soll spaeter
multiply: und condition: aufnehmen koennen (noch nicht
implementiert).

Begruendung: Erst stabilisieren, dann erweitern.

### 12. Prioritaet in port_scan._classify

port_scan > network_scan > brute_force.

Begruendung: Deterministische Klassifikation. brute_force ist
eigenstaendig und kann parallel auftreten — spaeter mehrere
Output-Events pro Regel.

### 13. AgentLoop ist stateless

policy_context wird pro run(event, policy_context=...) uebergeben,
nicht im Konstruktor gehalten.

Begruendung: Determinismus, keine Zustandslecks zwischen Events.

### 14. Globale vs. spezifische Policy-Pruefer

GLOBAL_PREDICATES (no_shell_chars, no_path_traversal,
no_null_bytes) laufen IMMER, unabhaengig von der Policy.
SPECIFIC_PREDICATES (authorized_target, read_only_path,
target_in_scope) laufen nur via conditions.

Begruendung: Sicherheitspruefer, die vergessen werden koennen,
sind keine Sicherheitspruefer.

### 15. Strengste Entscheidung gewinnt

FORBIDDEN > APPROVAL_REQUIRED > ALLOWED.

Weiche Pruefer (on_fail=APPROVAL_REQUIRED): Mensch kann
freigeben. Harte Pruefer (on_fail=FORBIDDEN): sofort blockiert.

Begruendung: Kein stiller Durchlauf bei Konflikten.

### 16. Kein eval, kein DSL in der Policy Engine

Pruefer-Namen in YAML, Implementierung in Python. Unbekannter
Name -> PolicyError beim Laden.

Begruendung: Deterministisch, auditierbar, keine
Injection-Angriffsflaeche.

### 17. Tools: func(**args), kein Context

Der AgentLoop ruft Tools mit Keyword-Argumenten auf. Tools
bleiben kontextfrei.

Begruendung: Testbar, deterministisch, keine implizite
Abhaengigkeit auf Umgebung.

### 18. source-Marker statt mock-Feld

Jedes Tool-Ergebnis traegt "source": "mock" | "db" | "nmap" |
"telegram" | ... Kein separates "mock"-Feld.

Begruendung: Eine Konvention, ein Marker. Werte wechseln, wenn
echte Ausfuehrung dazukommt.

### 19. Fail closed bei fehlender DB

get_devices und whitelist_check werfen ToolError, wenn die DB
fehlt. Kein stilles leeres Ergebnis.

Begruendung: Ein Tool, das stillschweigend leer liefert, ist
eine Sicherheitsluecke.

### 20. AgentLoop Policy-Check VOR Argument-Validierung

Reihenfolge im Loop:
Tool-Lookup -> Permission -> Level-4-Approval -> Policy
-> Argument-Validierung -> Ausfuehrung.

Begruendung: Policy kann Tools verbieten, unabhaengig von
Argumenten.

### 21. Service-interne RBAC-Helfer parametrisiert

Service-interne RBAC-Helfer nehmen den Permission-Code
als Parameter, nicht fest verdrahtet. Beispiel:

    def _require(self, actor, code):
        self._checker.require_permission(actor, code)

Aufrufstellen nennen den Code explizit:

    self._require(actor, "audit.read")
    self._require(actor, "alert.view")

Grund: eine Methode fuer mehrere Permissions, Code an
der Aufrufstelle sichtbar. Kein Helper pro Permission.

---

## 2. Audit-Nomenklatur

### agent

Immer "security_ai" in Phase 2b/3. Spaeter "admin_ai", wenn
die Admin AI dazukommt.

### tool = Komponente

| Komponente                     | tool                   |
|--------------------------------|------------------------|
| Orchestrator (Inventory)       | inventory_repository   |
| Orchestrator (Detection)       | detection_engine       |
| Orchestrator (Risk)            | risk_engine            |
| Orchestrator (Snapshot)        | orchestrator           |
| Orchestrator (Loop-Result)     | agent_loop             |
| AgentLoop (Tool-Call)          | telegram_alert, nmap_scan, etc. |
| ChatService (Service)          | chat_service           |
| AccessService (Service)        | access_service         |
| InventoryService (Service)     | inventory_service      |
| ApprovalService (Service)      | approval_service       |
| ChangeService (Service)        | change_service         |
| RateLimitService (Service)     | rate_limit_service     |
| CLI (approvals_cli)            | approvals_cli          |
| CLI (changes_cli)              | changes_cli            |

### details.kind = Aktion

- inventory_update
- detection_result
- risk_assessment
- snapshot
- loop_result
- tool_call
- tool_denied
- tool_approval_required
- tool_not_found
- tool_invalid_args
- loop_error

### details.action = konkrete Operation

Bei inventory_update:
- upsert_seen
- mark_offline
- record_history

### Phase 3.5: Chat-Kinds

- chat_query          (immer, vor RBAC)
- chat_answered       (Antwort erzeugt; source-Werte s. u.)
- chat_access_denied  (RBAC-Verweigerung)
- chat_llm_error      (LLM-Fehler, fail closed)
- chat_answer_contradicts_context
                      (Sanity-Check erkannte Widerspruch)
- chat_model_callback_failed
                      (on_model_selected warf Exception)

### source-Werte in chat_answered

| source         | Bedeutung                                    |
|----------------|----------------------------------------------|
| llm            | LLM-Antwort (concept oder interpretation)    |
| fact           | deterministische Faktenantwort (kein LLM)    |
| detail_append  | Detail-Anhang (kein LLM)                     |
| no_context     | Interpretation ohne Kontext (kein LLM)       |
| llm_retry      | Retry mit grossem Modell                     |

### Phase 4a: Approval-Kinds

Die Approval-Kinds sind in Abschnitt 6 dokumentiert.
Kurzliste: `approval_requested`, `approval_granted`,
`approval_rejected`, `approval_expired`,
`approval_notify_sent`, `approval_notify_failed`,
`approval_notify_skipped`, `approval_enqueue_failed`.

### Phase 4b: Change-Kinds

Change-Request-Kinds (Details in Abschnitt 7):
`change_created`, `change_approved`, `change_rejected`,
`change_deployed`, `change_rolled_back`,
`change_cancelled`.

### Approval-Benachrichtigung

Die Approval-Benachrichtigung ruft telegram_alert_run
direkt (nicht ueber die Registry). Verweis auf Abschnitt 9.
Audit-Kinds: approval_notify_sent, approval_notify_failed,
approval_notify_skipped.

### Filterbar per jq

    jq 'select(.details.kind == "risk_assessment"
               and .details.score > 0.8)' audit-logs/*.jsonl

    jq 'select(.details.action == "upsert_seen")' audit-logs/*.jsonl

    jq 'select(.details.kind | startswith("tool_"))' audit-logs/*.jsonl

---

## 3. Test-Ebenen

### Ebene 1 — Score-Regeln (tests/unit/test_risk.py)

Prueft konkrete Werte direkt:
base 0.5 + hauptnetz 0.2 + first_seen 0.15 = 0.85 -> CONFIRMED.

Aenderungen an rules.yaml brechen genau diese Tests.

### Ebene 2 — Kategorie -> Severity (tests/unit/test_planning.py)

Prueft das Mapping isoliert:
CONFIRMED -> CRITICAL, SECURITY_ALERT -> WARNING.

Kein Orchestrator, keine Detection.

### Ebene 3 — Kette (tests/integration/test_orchestrator.py)

Prueft Event -> Detection -> Risk -> Loop -> Tool. Severity
wird aus der Assessment-Kategorie ABGELEITET, nicht
hartkodiert:

    CATEGORY_TO_SEVERITY = {
        "EVENT": "INFO",
        "ANOMALY": "INFO",
        "SUSPICION": "WARNING",
        "SECURITY_ALERT": "WARNING",
        "CONFIRMED": "CRITICAL",
    }
    assessment = result.assessments[0]
    expected_severity = CATEGORY_TO_SEVERITY[assessment.category.value]
    assert mock_calls[0]["severity"] == expected_severity

Begruendung: Wenn sich Score-Regeln aendern, bricht nur Ebene 1.
Die Integrationstests bleiben stabil.

---

### Ebene 4 — Approval (tests/unit/test_approval_notify.py, tests/unit/test_approvals_cli.py)

- `test_approval_notify.py`: Hook isoliert, `telegram_alert_run`
  gemockt. 6 Faelle (disabled, status!=APPROVAL, ohne id, mit id,
  Telegram-Fehler, Audit bei Erfolg).
- `test_approvals_cli.py`: CLI mit tmp-SQLite-Datei (Migration
  laeuft). 11 Faelle.
- Integrationstest (spaeter, separat): in
  `tests/integration/test_orchestrator.py` als eigener Test
  (Alert + Approval = zwei Telegram-Nachrichten).

### Ebene 5 — Change Requests (tests/unit/test_changes.py, tests/unit/test_change_applier.py)

- `test_changes.py`: Parser (14), Repository (10), CLI (11).
  Parser-Roundtrip (`to_dict` -> `from_dict`), Zustandsfluss,
  CLI-Export, Audit-Kinds `change_*`.
- `test_change_applier.py`: Applier-Stub wirft
  `NotImplementedError`; `orchestrator.create_change_request`
  legt DRAFT an, Audit `change_created`.
- Integrationstest (spaeter): CLI + Applier + Audit in einer
  Kette, sobald der Applier echt ist.

### Namenskonvention fuer Tests

Verbindlich (siehe auch WORKFLOW.md Abschnitt
"Test-Konventionen (verbindlich)"):

- Klassen mit `*Tests`-Suffix erben von
  `unittest.TestCase`. Ohne Vererbung sammelt pytest
  sie nicht (Default `python_classes = Test*`).
- Alternativ: modulweite `def test_`-Funktionen
  (pytest-Standard).
- Klassen mit `Test*`-Praefix und ohne
  `unittest.TestCase` sind zulaessig, aber kein
  Mischstil in derselben Datei.
- Kein Wechsel ohne Doku-Block.

Beispiel: 3.6.14 `tests/unit/test_filters.py`. Erste
Version hatte Klassen mit `*Tests`-Suffix ohne
`unittest.TestCase`. `py_compile=OK`, aber
`pytest --collect-only -q` lieferte 0. Fix:
Vererbung ergaenzt.

## 4. Format und Prozess

- Keine Umlaute in Code-Bloecken (oe, ue, ae, ss).
- Kein sed auf Python-Code. Patches per Python-Skript
  (Path.read_text/replace/write_text).
- Nach jedem Schreiben: wc -l, py_compile, Test, git commit.
- Bei langen Dateien zwei oder drei Bloecke.
- Bei Fehlern: kurze Ursache, dann Fix, keine langen Vorreden.
- Auto-Fix-Regeln pruefen, nicht blind anwenden:
  siehe WORKFLOW.md, Abschnitt "Auto-Fix-Regeln pruefen,
  nicht blind anwenden" (B010/TypeVar, Punkt 41).
- Lint-Auflagen: erst messen, dann entscheiden.
  `ruff check --show-settings` zeigt die aktive
  Regel-Liste. `ruff check . --statistics` ist der
  reproduzierbare Stand. `--select <CODE>` forciert
  eine Regel, auch wenn sie nicht im Default-Satz
  waere. Keine Config-Aenderung ohne diese Messung.
  Siehe SECURITY_REVIEW_LOG Punkt 53.

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

## 6. Approval-Flow (Phase 4a)

### Rollen

- SQLite (`approvals`-Tabelle): Quelle der Wahrheit, Zustand.
- Telegram: Kanal (Benachrichtigung), kein Zustand.
- Audit-Log: Nachweis (jede Anfrage, jede Entscheidung).
- CLI (`scripts/approvals_cli.py`): alternative Bedienung.

Kein Entweder-oder. Telegram ODER DB war nie die Frage — beides
mit klaren Rollen. Kanal ist austauschbar (spaeter Web-UI, E-Mail,
Slack), Zustand bleibt in der DB.

### request_id-Format

- Format: `APR-YYYY-NNNNN` (z. B. `APR-2026-00001`).
- Jahresweise fortlaufend, 5-stellig, `zfill(5)`.
- Atomare Vergabe: `BEGIN IMMEDIATE`, `MAX`-Selektion gefiltert
  auf `LIKE 'APR-<jahr>-%'`, dann `INSERT`.
- Konsistent mit `CHG-YYYY-NNNNN` aus Phase 4b (Change Requests).
- Eindeutigkeit zusaetzlich durch `UNIQUE(request_id)` in der DB.

### Status-Werte (Phase 4a)

- `PENDING`, `GRANTED`, `REJECTED`, `EXPIRED`.
- `CANCELLED` und `SUPERSEDED` kommen spaeter per Migration,
  wenn sie gebraucht werden.
- `status` in der DB ist `TEXT` ohne `CHECK`-Constraint.
  Konvention im Code (`ApprovalStatus`), nicht in der DB.
  (Konsistent zu `device_history.event_type`, Entscheidung 5.)

### DB-Schema

`data/migrations/0003_approvals.sql`:

- `id` (PK, AUTOINCREMENT)
- `request_id` (TEXT, UNIQUE)
- `timestamp` (TEXT, fachlicher Zeitpunkt)
- `tool_name` (TEXT)
- `args_json` (TEXT, JSON)
- `requested_by` (TEXT)
- `reason`, `risk_category`, `risk_score`, `event_id`
- `status` (TEXT, Default `'pending'`)
- `decided_at`, `decided_by`, `decision_reason`
- `expires_at` (TEXT, nullable)
- `created_at` (TEXT, technischer Zeitpunkt)
- Index `idx_approvals_status`, `idx_approvals_request_id`.

`timestamp` und `created_at` sind bewusst getrennt: `timestamp`
ist fachlich (aus Sicht des Events), `created_at` technisch
(Zeitpunkt des `INSERT`).

### Audit-Kinds (Ergaenzung zu Abschnitt 2)

- `approval_requested`  — neue Request angelegt
- `approval_granted`    — GRANTED
- `approval_rejected`   — REJECTED
- `approval_expired`    — EXPIRED
- `approval_notify_sent`    — Telegram-Benachrichtigung erfolgreich
- `approval_notify_failed`  — Telegram-Benachrichtigung fehlgeschlagen
- `approval_notify_skipped` — Kanal deaktiviert (`enabled: false`)
- `approval_enqueue_failed` — DB-Schreibfehler beim Anlegen

### Fail-closed und Fail-open

Fail-closed (Sicherheit und Zustand):

- `ApprovalQueue.enqueue`: DB zuerst, Audit zweitens.
  DB-Fehler -> `ApprovalEnqueueError`, kein Audit.
  Audit-Fehler -> `AuditWriteError`, DB-Eintrag bleibt.
- AgentLoop: bei `ApprovalEnqueueError` Audit-Eintrag
  `approval_enqueue_failed` + `raise`. Kein stiller Fallback.
- `decide`: nur `PENDING -> GRANTED|REJECTED`. Anderer Zustand
  -> `ApprovalStateError`. Race-Schutz via `rowcount == 0`.

Fail-open (bewusst, nur Benachrichtigung):

- `_notify_approval`: Fehler beim Telegram-Versand werden
  abgefangen, auditiert (`approval_notify_failed`) und **nicht**
  propagiert.
  Begruendung: DB ist Wahrheit, Loop-Status ist APPROVAL_REQUIRED,
  der Mensch kann via CLI entscheiden. Telegram ist Kanal, nicht
  Zustand. Fail-closed gilt fuer Sicherheitsaktionen, nicht fuer
  Benachrichtigungen.

### Trennung: Loop entscheidet nicht

Der AgentLoop entscheidet **nicht** ueber Approval. Er legt nur
an (`enqueue`) und pausiert (`status="APPROVAL_REQUIRED"`). Die
Entscheidung faellt ausserhalb des Loops:

- heute: CLI (`scripts/approvals_cli.py`)
- spaeter: Telegram-Bot-Listener (`/approve`, `/reject`)

Der Loop bleibt stateless (Entscheidung 13).

### Sicherheitsregel: `--by` ist Pflicht

CLI `approve`/`reject` verlangen `--by <name>`. Ohne
Entscheider kein Zustandswechsel. Der Name landet in
`decided_by` und im Audit. `--reason` ist bei `reject` empfohlen.

### Notiz fuer spaeter (nicht bauen)

Viele `PENDING`-Approvals in kurzer Zeit -> Eskalation auf
`CRITICAL`-Benachrichtigung. Nicht Teil von Phase 4a.

## 7. Change Requests (Phase 4b)

### Rollen

- SQLite (`change_requests`-Tabelle): Quelle der Wahrheit.
- JSON-Dateien in `changes/`: Export, versioniert in Git,
  fuer Foederation (MCP) und Signierung.
- Audit-Log: Nachweis jeder Erstellung und jedes Uebergangs.
- CLI (`scripts/changes_cli.py`): Bedienung.

### change_id-Format

- Format: `CHG-YYYY-NNNNN` (z. B. `CHG-2026-00001`).
- Jahresweise, 5-stellig, atomar (wie `APR-...` fuer Approvals).
- `UNIQUE(change_id)` in der DB.

### Status-Werte (Phase 4b)

- DRAFT, TESTING, PENDING_REVIEW, APPROVED, DEPLOYED,
  ROLLED_BACK, REJECTED, CANCELLED.
- Konsistent mit docs/PROTOCOL.md, Abschnitt 4.

### Typ-Werte

- config_change, code_change, policy_change,
  firewall_change, device_whitelist_change.
- Der Applier entscheidet spaeter anhand des Typs, welche
  Aktion ausgefuehrt wird.

### Zustandsfluss (Quelle der Wahrheit: repository._ALLOWED_TRANSITIONS)

    DRAFT           -> {TESTING, PENDING_REVIEW, REJECTED, CANCELLED}
    TESTING         -> {PENDING_REVIEW, REJECTED, CANCELLED}
    PENDING_REVIEW  -> {APPROVED, REJECTED, CANCELLED}
    APPROVED        -> {DEPLOYED, CANCELLED}
    DEPLOYED        -> {ROLLED_BACK}
    ROLLED_BACK     -> {}
    REJECTED        -> {}
    CANCELLED       -> {}

Bewusste Entscheidung: kein Uebergang APPROVED -> REJECTED.
Wer freigegeben hat, kann den Change nur deployen oder vom
Antragsteller zurueckziehen lassen (CANCELLED).

CANCELLED = Antragsteller zieht zurueck.
REJECTED  = Reviewer lehnt ab.

### DB-Schema

`data/migrations/0004_change_requests.sql`:

- Pflicht: change_id, timestamp, title, description,
  requested_by, status, type, created_at.
- Optional: diff_or_patch, files_affected (JSON-Text),
  rollback_plan, test_plan, related_approval_id,
  related_event_id, risk_category, risk_score,
  decided_at, decided_by, decision_reason,
  deployed_at, rolled_back_at.
- status und type sind TEXT ohne CHECK (Konvention im Code).
- files_affected als JSON-Text, weil SQLite kein Array hat.

### Audit-Kinds

- change_created
- change_approved
- change_rejected
- change_deployed
- change_rolled_back
- change_cancelled (nach Code-Anpassung CANCELLED)

### Applier-Stub

`harness/versioning/applier.py`:

- `ChangeApplier.apply(change)` und `.rollback(change)` werfen
  `NotImplementedError`.
- Bewusste Entscheidung: kein silent no-op. Sonst koennte ein
  APPROVED Change als DEPLOYED markiert werden, ohne
  tatsaechlich angewendet worden zu sein.
- Konstruktor nimmt `**deps` entgegen, damit spaetere
  Implementierung die Signatur nicht aendert.

### Trennung: Loop legt keine Changes an

`create_change_request` liegt am Orchestrator (kennt DB + Audit).
Der AgentLoop legt **keine** Change Requests an — analog zu
Approval: die Entscheidung faellt ausserhalb des Loops.

### Notiz fuer spaeter (nicht bauen)

- `ChangeApplier.apply`: Config-Schreiben, Policy-Reload,
  Firewall-Call, je nach type.
- `ChangeApplier.rollback`: nutzt rollback_plan aus dem JSON.
- Signierung der JSON-Exporte (HMAC) fuer Foederation.

## 9. Approval-Benachrichtigung ruft telegram_alert_run direkt

_notify_approval ruft telegram_alert_run DIREKT auf —
nicht ueber die Tool Registry, nicht ueber den Agent Loop.

### Begruendung

- Es ist eine Benachrichtigung, keine Aktion. Wie ein
  Log-Eintrag, nur ueber einen anderen Kanal.
- Keine Policy dafuer: "Darf ich eine Approval-
  Benachrichtigung schicken?" ist eine Betriebsfrage, keine
  Sicherheitsfrage.
- Kein Approval fuer eine Approval-Benachrichtigung
  (rekursiv).
- Die DB ist die Quelle der Wahrheit. Die Benachrichtigung
  ist best effort. Wenn sie fehlschlaegt, ruft der Mensch
  die CLI auf.

### Konsequenz

- _notify_approval faengt Telegram-Fehler ab, propagiert
  sie nicht.
- Audit-Kinds: approval_notify_sent,
  approval_notify_failed, approval_notify_skipped.
- enabled=False -> no-op + Audit approval_notify_skipped.

Der normale Alarm-Pfad (ueber Agent Loop) bleibt
unveraendert.

### Abgrenzung

- Alarm-Pfad (Agent Loop, Tool Registry, Policy, Audit
  tool_call): unveraendert.
- Approval-Anlage selbst laeuft ueber die DB
  (ApprovalQueue.enqueue), nicht ueber die Registry.
- Approval-Benachrichtigung ist der einzige Pfad, der
  telegram_alert_run direkt ruft.

## 10. RBAC (Rollen, Permissions, Principals)

### Grundmodell

Drei Entitaeten in SQLite (Migration 0005):

- permissions: feingranulare Codes (chat.ask, approval.decide, ...).
- roles: benannte Rollen (admin, operator, viewer, system).
- role_permissions: n:m zwischen Rollen und Permissions.
- principals: alles, was authentifiziert werden kann.

### Principal statt User

"Principal" ist der Fachbegriff fuer eine Entitaet, die
authentifiziert werden kann. Nicht nur Menschen.

kind:
- human   — Mensch
- system  — interne Komponente (security_ai, host_scanner)
- service — externer Service (admin_ai, api_client)

password_hash NULL = kein Login (z. B. cli-admin).
is_active False = gesperrt.

### Permissions (Phase 3.5)

chat.ask, chat.detail, chat.include_details,
device.read, device.write,
approval.view, approval.decide,
change.view, change.create, change.decide, change.deploy,
audit.read, audit.write,
principal.manage, role.manage

### Rollen und Zuordnung

- admin    -> alle
- operator -> chat.*, device.read, approval.view, approval.decide,
              change.view, change.create, change.decide, audit.read
- viewer   -> chat.ask, device.read, audit.read
- system   -> chat.ask, device.read, audit.write

### Web-Login-Regel (Punkt 3, 2026-09-27)

Ein Principal, der sich einloggen koennen soll,
braucht eine Rolle mit `device.read`.
`AccessService.create_principal` erzwingt das und
wirft `AccessServiceError` bei Rollen ohne
`device.read`.

Fail-closed-Zeitpunkt verschoben: vom Login (spaet)
zum Anlegen (frueh). Rollen ohne `device.read`
bleiben fuer Nicht-Login-Zwecke zulaessig
(z. B. Service-Rollen).

### Chat-Rate-Limit-Store (Punkt 9, c4a1fa0)

RateLimitService nutzt SQLite (chat_rate_hits),
Multi-Worker-fest und Fail closed bei Fehler.
Login-Rate-Limit bleibt getrennt in login_attempts.

### Fail closed

- AccessChecker.has_permission -> False bei jedem Fehler
  (Principal unbekannt, inaktiv, Permission-Code unbekannt).
- AccessChecker.require_permission -> AccessDeniedError.
- Kein Wildcard, kein Prefix-Match. Nur exakte Codes.
- require_permission bleibt im Checker: er ist die zustaendige
  Stelle fuer "darf nicht". Ein Aufrufer, der selbst raise
  macht, wird vergessen, es zu tun. Der Checker nicht.

### Passwort-Hashing (Phase 3.6)

- pbkdf2_sha256, 600_000 Iterationen (OWASP 2023).
- Format: pbkdf2_sha256$600000$<salt_hex>$<hash_hex>.
- In Phase 3.5 noch nicht genutzt: cli-admin laeuft ohne Login.
- Passwort-Login kommt mit dem Web-Dashboard.

## 11. Service-Schicht

### Drei Schichten

1. UI (Web Flask, CLI, Telegram) — ruft nur Services.
2. Service-Schicht (core/services/) — Fachlogik,
   Berechtigungspruefung, Audit.
3. Repositories (core/access, core/approval, core/changes,
   core/inventory) — DB-Zugriff.

### Beispiel

    AccessService.create_principal(actor, name, role_name, ...):
        - Berechtigung pruefen (principal.manage)
        - Validierung
        - repo.create(...)
        - audit.log(principal_created)

Web-Route, CLI und Telegram rufen denselben Service. Keine
Fachlogik in der UI.

### Audit ist Pflicht in der Service-Schicht

- Jede schreibende Service-Methode ruft audit.log(...).
- details.kind ist die Aktion (z. B. principal_created,
  permission_assigned).
- Fehlt der AuditWriter, wirft der Service (fail closed).

### Fehlerklassen in der Service-Schicht (3.6.8d)

Seit 3.6.8d gibt es zwei Basis-Fehlerklassen in
core/services/errors.py:

- ServiceError    = fachlicher/Format-Fehler -> 4xx
                    Ungueltige Eingabe, fehlende
                    Pflichtfelder, Formatfehler.
- OperationError  = Betriebsfehler -> 5xx
                    DB-Fehler, Audit-Fehler,
                    unerwartete Laufzeitfehler.

OperationError ist bewusst NICHT Subklasse von
ServiceError, damit ein `except ServiceError` im
Route-Handler den Betriebsfehler NICHT faengt und der
globale 500-Handler greifen kann.

Regel: Format-Fehler -> ServiceError-Subklasse -> 4xx.
       Betriebs-Fehler -> OperationError-Subklasse -> 5xx.

Vorbild: ChangeService (3.6.8d) mit ChangeServiceError
(ServiceError) und ChangeOperationError (OperationError).

Stand 3.6.15c: Alle vier Kern-Services haben jetzt die
Trennung:
- ChatService:        ChatServiceError (ServiceError) /
                      ChatOperationError (OperationError).
                      LLMError/LLMTimeout/LLMUnavailable
                      bleiben roh (502 Upstream).
- ApprovalService:    ApprovalServiceError (ServiceError) /
                      Repo-Fehler propagieren (Variante D,
                      siehe Regel unten).
- InventoryService:   InventoryServiceError (ServiceError) /
                      InventoryOperationError (OperationError).
- AuditReaderService: AuditReaderServiceError (ServiceError) /
                      AuditReaderOperationError (OperationError).

Regel (3.6.15c, Auflage 506): Repo-Fehler mit semantischer
Bedeutung (NotFound, State) werden nicht in ServiceError
gewickelt. Die Route behandelt sie direkt:
  ApprovalNotFoundError -> 404.
  ApprovalStateError    -> 409.
Die Basisklasse ApprovalRepositoryError wird NICHT
gefangen -> globaler 500.
LLM-Fehler werden nicht in OperationError gewickelt.
Sie haben eigene Semantik (502 Upstream).

### Wert-Synonyme fuer die Suche (Punkt 29)

Suchbegriffe werden auf Synonym-Zielwerte erweitert
(core/search/synonyms.yaml + synonyms.py).
Beispiel: "alarm" -> category=SECURITY_ALERT.
Nur Werte, nicht Quellen. Die normale String-Suche
bleibt zusaetzlich. Dedup pro Quelle (Audit-ID,
Request-ID, Change-ID). Kein Regex, kein Stemming.

### Suchfelder pro Quelle (Auflage 530, 3.6.16)

Suchfelder pro Quelle werden in Auflage 530 (3.6.16)
definiert. Bei jeder Aenderung an einer Quelle pruefen,
ob ein Feld ergaenzt oder entfernt werden muss.
Stand 3.6.18a: category bei risk_assessments ergaenzt.

### Kontext-Aufbau fuer den Chat (Punkt 28)

Der Kontext fuer ChatService.ask liegt in
core/context/builder.build_chat_context.
Kein RBAC, kein Audit. Wird von CLI
(scripts/chat_cli.py) und Dashboard
(apps/dashboard/routes_chat.py) genutzt.
Log-Excerpts und recent_events sind leer
(Auflagen 720/721).

### ChatService — entfernt (Phase 16)

Der ChatService (apps/security_ai/chat.py) und
der zugehoerige Kontext-Bauer wurden mit dem
Ollama-Rueckbau (Phase 16) entfernt. Die
Intelligenz-Schicht wird von der Admin AI
uebernommen (siehe docs/ADMIN_AI_SCOPE.md).

Die nachfolgende Beschreibung bleibt als
historischer Bezug stehen. Sie ist nicht mehr
aktiv.


- Nutzt AccessChecker (RBAC).
- Nutzt ContextBuilder (harness/context).
- Nutzt LLMClient (harness/llm).
- LLM entscheidet nichts. Der Service ruft nur das LLM, um
  eine Antwort zu formulieren.
- Fail closed bei RBAC UND bei LLM-Fehler: LLMError wird
  propagiert. Ein Chat, der eine erfundene Antwort liefert,
  ist schlimmer als einer, der "nicht erreichbar" sagt.

### Audit-Kinds (Phase 3.5, Chat)

- chat_query          (immer, vor RBAC)
- chat_access_denied  (bei RBAC-Verweigerung: chat.ask,
                       chat.include_details, chat.detail)
- chat_answered       (bei erfolgreicher Antwort)
- chat_llm_error      (bei LLM-Fehler)

Die Frage selbst landet NICHT im Audit. Stattdessen:
- question_hash (sha256, 64 Hex)
- question_hash_short (erste 16 Hex)

### Detail-Anhang ohne LLM

Wenn die Frage nach einer IP fragt (Regex) oder detail=True
gesetzt ist, wird der Detail-Pfad genutzt:
- kein LLM-Aufruf,
- Antwort direkt aus dem Kontext (Event-Identifier +
  inventory.recently_added + recently_offline),
- Dedup via set, sortierte Ausgabe,
- braucht die Permission chat.detail.

### Modellwahl

- Default: llama3.2:3b (schnell, CPU-tauglich).
- Large: qwen2.5:7b (langsam, tiefere Fragen).
- Konfiguration in .env: OLLAMA_BASE_URL,
  SECURITY_AI_MODEL, SECURITY_AI_MODEL_LARGE.
- Der Client bleibt dumm: Modell ist Parameter mit Default
  aus harness.llm.models. ChatService liest den Default
  aus core.config.

### Was Phase 3.5 NICHT macht

- Kein Web-Dashboard (Phase 3.6).
- Kein Login (Phase 3.6).
- Kein Streaming (spaeter).
- Keine Session-Historie (harness/memory, spaeter).

## 12. Auto-Switch zu grossem Modell — obsolet nach Ollama-Rueckbau

Begruendung: das lokale 3B-Modell liefert
keine brauchbaren Antworten fuer die Komplexitaet
der Aufgaben. Ersetzt durch Cloud-Provider
(siehe docs/ADMIN_AI_SCOPE.md, Phase 13, und
SECURITY_REVIEW_LOG Punkt 88).

(Historischer Inhalt, nicht mehr aktiv.)

--- Ab hier: der bisherige § 12-Inhalt ---

### Prinzip

Zustandsfragen mit kritischen Assessments werden mit dem
grossen Modell beantwortet (qwen2.5:7b). Alle anderen Fragen
mit dem Default (llama3.2:3b).

Grund: Das 3B-Modell erkennt zwar die Zahlen, interpretiert
sie aber falsch ("keine Auffaelligkeiten" bei 31 CONFIRMED).
Das 7B-Modell beantwortet dieselbe Frage korrekt, ist auf
CPU-only aber deutlich langsamer (1-3 Minuten).

### Regel

    if explicit_model:
        -> explicit_user
    elif auto_large and is_critical_state_question:
        -> auto_critical_state
    else:
        -> default

Kritisch = _is_state_question(question) UND
           risk_assessments enthaelt CONFIRMED oder
           SECURITY_ALERT.

auto_large ist Default True, per --no-auto-large oder
ChatService(auto_large=False) abschaltbar. Aber:
- Fakt-Fragen gehen nie ans LLM (Abschnitt 14).
- Concept-Fragen ignorieren den Auto-Switch (Abschnitt 14).
- Der Sanity-Check bleibt unabhaengig von auto_large aktiv.

### Timeouts

Modellabhaengig:

    llama3.2:3b  -> 30 s
    qwen2.5:7b   -> 180 s
    unbekannt    -> 60 s

--timeout ueberschreibt.

### Transparenz

ChatResponse.model_reason: "default" | "auto_critical_state" |
"explicit_user".

CLI zeigt:

    [Modell: qwen2.5:7b -- auto_critical_state]
    [Auto-Switch zu grossem Modell -- kann 1-3 Minuten dauern]

### Audit

chat_answered enthaelt model und model_reason. Damit ist
nachvollziehbar, welches Modell mit welcher Begruendung
geantwortet hat.

### Auto-Switch ist PFLICHT bei kritischen Assessments

llama3.2:3b ist bei kritischen Assessments unzuverlaessig.
Zwei Live-Tests haben das gezeigt:

1. Phase 3.5.7: Antwort "NEIN, keine Auffaelligkeiten"
   trotz 31 CONFIRMED + 12 SECURITY_ALERT im Kontext.
2. Phase 3.5.9: Antwort "7 SUSPICION-Auffaelligkeiten"
   trotz 31 CONFIRMED (Underreporting).

Beide Faelle sind kein Prompt-Problem. Ein 3B-Modell kann
nicht zuverlaessig schliessen.

Konsequenz:

- Auto-Switch zu qwen2.5:7b bei Interpretation mit kritischen
  Assessments ist PFLICHT, nicht Robustheit.
- --no-auto-large riskiert Underreporting. CLI-Warnung.
- Der Sanity-Check (Denial + Underreporting) ist NICHT durch
  auto_large abschaltbar. Sicherheitsschicht.
- Der Sanity-Check greift nur bei Interpretation, nicht bei
  concept (Konzeptfragen reden nicht ueber den Kontext).

### Abgrenzung zu Fakt-Fragen

Faktenfragen ("Gab es Auffaelligkeiten?", "Wie viele Events?")
laufen NICHT ans LLM. Sie sind deterministisch (Abschnitt 14).
Der Auto-Switch ist nur fuer Interpretationsfragen relevant.

### Modellwahl bleibt Empfehlung (nur bei Interpretation)

Wenn keine kritischen Assessments vorliegen, ist die
Modellwahl eine Empfehlung. Der Mensch kann mit --model
eingreifen. Bei kritischen Assessments greift die Pflicht.

## 14. Frage-Klassifikation — obsolet nach Ollama-Rueckbau

Begruendung: die Klassifikation war fuer das
lokale Modell gedacht. Cloud-Provider
uebernehmen die Klassifikation selbst. Siehe
docs/ADMIN_AI_SCOPE.md, Phase 13, und
SECURITY_REVIEW_LOG Punkt 88.

(Historischer Inhalt, nicht mehr aktiv.)

--- Ab hier: der bisherige § 14-Inhalt ---

### Drei Arten von Fragen

1. fact            -> deterministische Antwort aus context,
                      KEIN LLM-Aufruf.
2. concept         -> LLM (3B), kein Kontext-Zwang.
3. interpretation  -> LLM mit Kontext (7B via Auto-Switch).

### Regex

    _FACT_RE:
        wie viele | wieviele | welche kategorien |
        wie hoch | wie oft | wie lange |
        gab es | gibt es | gibts | gibt's |
        liste | zeig mir

    _CONCEPT_RE:
        was ist | was bedeutet | wie funktioniert |
        erklaere | was sind

    Reihenfolge (3.6.15d, Auflage 513; erweitert um
    Veto, Punkt 32, Auflagen 805-811):
      if _FACT_RE and not _has_critical_state_word(q): fact
      elif _CONCEPT_RE and not _is_state_question: concept
      sonst: interpretation

    Veto (Punkt 32, A805/A806): _has_critical_state_word
    prueft die Frage gegen _CRITICAL_STATE_WORDS. Nur
    Woerter, die eine Bewertung implizieren:
      kritisch, alarm, vorfall, vorfaelle, vorfaellen,
      bestaetigt, confirmed, security_alert,
      security-alert, suspicion, verdacht, warnung,
      warnungen.
    "Auffaellig" ist bewusst NICHT dabei (Sachverhalts-
    frage, kein Bewertungswort). "Status", "Info",
    "Event" sind bewusst NICHT dabei (zu breit).
    _is_state_question bleibt unveraendert (breitere
    Semantik fuer den Auto-Switch); das Veto fuer den
    fact-Pfad ist eine eigene, engere Regel.

    Wichtig (3.6.15d): concept nur, wenn NICHT
    Zustandsfrage. "Was ist heute Nacht passiert?"
    matcht _CONCEPT_RE, ist aber Zustandsfrage und
    muss als interpretation laufen (Kontext + 7B).

Hinweis: "welche IP" ist Detail, NICHT Fact.
Der Detail-Pfad greift VOR dem Fact-Pfad.

### Reihenfolge in ask()

1. chat_query (immer, vor RBAC)
2. RBAC chat.ask
3. Detail-Pfad (Detail-Regex ODER --detail Flag)
4. Fact-Pfad (_FACT_RE, context.has_data())
5. no_context-Pfad (Interpretation + Zustandsfrage ohne Kontext)
6. Concept-Pfad (_CONCEPT_RE, LLM mit default_model)
7. Interpretation-Pfad (LLM, Auto-Switch bei kritisch)

### source-Werte

- "detail_append"  Detail
- "fact"           Faktenantwort
- "no_context"     keine Daten fuer Interpretation
- "llm"            Concept oder Interpretation
- "llm_error"      LLM-Fehler

### Warum das die richtige Architektur ist

Ein LLM darf keine Fakten erfinden. Ein 3B-Modell schliesst
falsch. Ein 7B-Modell ist zu langsam fuer jede Frage.

Konsequenz: Alles, was deterministisch aus dem Kontext
ableitbar ist, wird deterministisch beantwortet. Das LLM
macht nur, was es wirklich kann: formulieren und
interpretieren.

### Auto-Switch-Bedingung (3.6.15d, Auflage 507)

Auto-Switch zu 7B greift bei JEDER Interpretation mit
kritischen Assessments (CONFIRMED, SECURITY_ALERT),
nicht nur bei Zustandsfragen.

Begruendung: Bei 91 kritischen Assessments ist der
Zustand der Welt selbst der kritische Fakt. Wer in
dieser Lage eine Interpretationsfrage stellt, braucht
eine Antwort, die den Zustand beruecksichtigt.
Zustandsfrage-Erkennung per Regex ist nicht mehr
Voraussetzung fuer den Auto-Switch.

Concept-Fragen bleiben 3B ohne Kontext (Auflage 517):
Wer nach der Definition eines Portscans fragt, will
keine Zustandsanalyse.

### --no-auto-large bleibt

Trotz fact-Pfad bleibt --no-auto-large sinnvoll:
- Bei Interpretationsfragen mit kritischen Assessments
  ist 3B unzuverlaessig.
- Der Nutzer kann es bewusst abschalten (Tests, Debugging).

### Sanity-Check (Phase 3.5.9, spaeter)

Wenn interpretation und LLM-Antwort dem Kontext widerspricht:
- Audit chat_answer_contradicts_context.
- Optional Retry mit 7B.

### Anzeige-Labels und Zeitraum im Fact-Pfad (Punkt 31)

Der Fact-Pfad nutzt die Anzeige-Labels aus
core/risk/models.py (CATEGORY_LABELS). Rohkategorien
werden nicht angezeigt (Auflage 829).
Reihenfolge nach Schweregrad absteigend:
CONFIRMED, SECURITY_ALERT, SUSPICION, ANOMALY, EVENT.
Der Begriff "Assessments" wird im Fact-Text durch
"Vorkommen" ersetzt.

ChatService.ask nimmt since_hours (Default 24). Der
Wert fliesst in ContextBundle.since_hours und wird
in _answer_fact zur Anzeige genutzt (Auflage 854).

## 15. Redaction / Prompt-Injection-Schutz (Phase 3.5)

> Hinweis (2026-10-04): Redaction wird fuer
> Cloud-LLM weiter genutzt — sogar wichtiger,
> weil Cloud bedeutet, dass Daten das Haus
> verlassen. Der folgende Abschnitt beschreibt
> Regeln, die weiterhin gelten.

### Prinzip

Rohdaten (Events, Logs, DB-Felder) werden gefiltert, bevor
sie ans LLM gehen. Das LLM sieht nur, was der Kontext-Bauer
freigibt.

Modul: `harness/context/redaction.py`.

### Regeln

- Steuerzeichen entfernen: \x00, \r, \x0b, \x0c.
  (\t und \n bleiben, mehrzeilige Logs sind erlaubt.)
- Instruktions-Marker entfernen (case-insensitive):
  "ignore previous", "ignore all", "ignore the above",
  "system:", "assistant:", "user:",
  "<|im_start|>", "<|im_end|>", "###instruction",
  "[inst]", "[/inst]", "<<sys>>", "<</sys>>".
- Laenge begrenzen: Default 2000 Zeichen, dann [REDACTED].
- Bei Verstoss: Passage durch [REDACTED] ersetzen.

### API

- redact_text(text, max_len) -> (str, bool)
- redact_field(value, max_len) -> (str, bool)
- redact_mapping(dict, max_len) -> (dict, bool)

Fail closed: Nicht-String -> ("", True) (markiert als
redigiert).

### ContextBundle.redacted

Der Kontext-Bauer setzt `redacted=True`, sobald mindestens
eine Redaktion stattfand. Der Chat-Prompt weist das Modell
darauf hin.

### Was NICHT gefiltert wird

- Risk-Assessments (strukturierte Objekte, kein Freitext).
- Approvals, Changes (strukturierte Objekte).
- Inventory-Snapshot (Aggregate).

Nur Freitext (Log-Ausschnitte, Feld-Werte) wird redigiert.

### Audit

Redaction selbst wird nicht auditiert (Performance). Der
redacted-Flag im Kontext ist ausreichend. Wenn im Prompt
`- Hinweis: Kontext wurde redigiert.` steht, weiss der
Nutzer, dass Redaktion stattfand.

### Abgrenzung zu Sanity-Check (§ 14)

- Redaction: schuetzt vor Injection **vom Kontext ins LLM**.
- Sanity-Check: schuetzt vor falschen **Antworten des LLM**
  (Denial, Underreporting).

## 16. Web-Dashboard-Sicherheit (Phase 3.6.7)

### CSP streng ohne unsafe-inline

Der CSP-Header ist streng:

    default-src 'self';
    script-src 'self';
    style-src 'self';
    img-src 'self' data:;
    font-src 'self';
    connect-src 'self';
    frame-ancestors 'none';
    base-uri 'self';
    form-action 'self';
    object-src 'none'

Kein 'unsafe-inline', kein 'unsafe-eval'.

Grund: Style-Injection ist ein realer XSS-Vektor
(CSS-Exfiltration, Clickjacking-Vorbereitung).
'unsafe-inline' in style-src schwaecht die ganze CSP.

Konsequenz:

- Kein `style="..."` in Templates.
- Kein `<style>`-Block.
- Kein `onclick=`, `onchange=`, `onsubmit=` usw.
- Kein inline `<script>`.
- Externe Stylesheets und Scripts nur lokal.

Dynamische Styles (Chart-Balken, Progress) nur via
`element.style.setProperty(...)` in JS. `<div
style="width:50%">` wird von `style-src 'self'`
blockiert. `el.style.width = "50%"` ist erlaubt
(CSSOM wird nicht von style-src blockiert).

### Weitere Security-Header

    X-Content-Type-Options: nosniff
    X-Frame-Options: DENY
    Referrer-Policy: same-origin
    Permissions-Policy: geolocation=(), camera=(),
                        microphone=(), payment=(),
                        usb=(), interest-cohort=()

### after_request

Alle Security-Header werden in `@app.after_request`
gesetzt. Greift auch auf 500er und Redirects.

### CSRF-Makro

`_helpers.html` enthaelt `csrf_field(token)` als Makro.
Token wird als Kontext-Variable uebergeben (nicht als
globale Jinja-Funktion). Kein context_processor.

### |safe-Verbot

`|safe` nur mit:

1. Dokumentation in dieser Datei.
2. Test in `tests/unit/test_templates_xss.py`.

Kein `|safe` fuer User-Input.

### _safe_next (Open-Redirect-Schutz)

`_safe_next(raw)` schuetzt vor Open-Redirect:

- Blockt `""` (leer) -> `/`
- Blockt Werte ohne fuehrendes `/`
- Blockt `//` (protokoll-relativ)
- Blockt `/\` (Backslash-Bypass in Chrome)
- Blockt `\r`, `\n`, `\x00` (Header-Injection)
- URL-Decode einmal (urllib.parse.unquote) VOR der
  Validierung: `%2F%2Fevil.com` und `/%%5Cevil.com`
  werden erkannt.

### html.escape in auth.py entfernt

`login_form` uebergibt `next` **roh** an das Template.
Jinja escaped automatisch (`autoescape=True`).
Doppeltes Escaping (`html.escape` + Jinja) wuerde
`&amp;lt;` statt `&lt;` erzeugen.

### stat_card.html als Makro

`{% include "x.html" with a=1 %}` ist **keine** gueltige
Jinja2-Syntax. Fuer Partial-Parameter wird ein Makro
verwendet:

    {% macro stat_card(label, value, accent="cyan") %}
    <div class="card card-accent-{{ accent }}">
      <div class="card-label">{{ label }}</div>
      <div class="card-value">{{ value }}</div>
    </div>
    {% endmacro %}

### Test-Fixtures in _helpers.py

Dashboard-spezifische Fixtures (`build_dashboard_app`,
`set_session_cookie`) liegen in
`tests/unit/_helpers.py`, NICHT in `tests/unit/conftest.py`.

Grund: `conftest.py` gilt fuer ALLE Unit-Tests. Andere
Tests koennten die dashboard-spezifische Fixture
versehentlich anfordern und einen unerwarteten Zustand
bekommen.

### venv und CWD

- Immer `/opt/security-ai/.venv/bin/python3`.
  Nicht `/usr/bin/python3`.
- Tests immer aus `/opt/security-ai` (CWD).
  Grund: `detection/rules.yaml`, `policies/tools.yaml`,
  `core/risk/rules.yaml` werden relativ zum CWD geladen.
- `scripts/*` sind Werkzeuge, keine Bibliothek.

### Test-Fixtures: Cookie-Flags

Der Test-Client setzt Session-Cookies mit den gleichen
Flags wie die Produktion:

    secure=True, httponly=True, samesite="Strict"

Sonst wird nicht das echte Verhalten getestet.

### HTML-Formular login

`login.html` ist standalone (kein `extends base.html`):

- Kein Sidebar, kein Topbar.
- Eigenes `<head>` mit CSS-Links.
- `variables.css` ZUERST, dann `reset.css`,
  `layout.css`, `components.css`, `main.css`.
- Kein `chat.css` (Login hat keinen Chat).
- CSRF-Feld via `csrf_field(token)`-Makro.
- `action="/login"` (doppelte Quotes).


### display: block auf .table (CSP-relevant, 3.6.10)

Eine Aenderung der Tabellen-Semantik (display: block auf
.table) wuerde die Spaltenberechnung aushebeln und ist
CSP-relevant. Sie wird nicht verwendet.

Responsive Loesung heute (3.6.10):
- table-layout: fixed + word-break fuer die Zellen.
- nowrap+ellipsis fuer die Zeitstempel-Spalte (14ch).
- nth-child(n+4) display: none bei <500px.

### Globale Suche (3.6.16)

- Neue Permission search.run (Migration 0008).
  admin + operator. viewer + system NICHT.
- GET /search?q=..., rein lesend, kein CSRF.
- Query-Validierung im Service (A538):
  Laenge 2-200, Zeichen-Whitelist [A-Za-z0-9 ._:/@-].
- LIKE '%q%' mit LOWER() und ESCAPE (A527/A528):
  %, _, \\ werden escaped. Keine Wildcard-Injektion.
- Nur identifizierende Felder durchsuchen (A530).
  Keine Freitextfelder (description, diff_or_patch,
  rollback_plan, test_plan, args_json, decision_reason,
  notes).
- Permission pro Quelle (A525/A526). Quellen ohne
  Permission werden aus dem Ergebnis entfernt, ohne
  Hinweis auf ihre Existenz.
- 20 Treffer pro Quelle, kein "Erste 20 von N"
  (A531/A371).
- Link-Builder als Jinja-if-Baum pro Quelle (A545),
  kein generischer Pfad.
- Schichtung: SearchService -> SearchRepository -> DB.
  Kein Service baut SQL. Keine bestehenden Repos
  angefasst (A553-A557).
- risk_assessments kommen aus JSONL (read_risk_assessments),
  Python-Filter im SearchService (A557).

### Links im Chat (Punkt 30, Auflagen 757-772)

fact/detail_append-Antworten liefern eine
strukturierte Link-Liste (core/context/links.py).
Regeln:
- Nur interne Pfade (Whitelist: /audit/, /changes/,
  /approvals/, /inventory/, /users/, /roles/).
  Kein externer Link, kein mailto, kein javascript:.
- RBAC pro Link (AccessChecker.check).
- Kein Href aus dem Text (Href wird aus der ID gebaut).
- Label = Rohstring, Client rendert via textContent.
- LLM-Antworten werden nicht verlinkt (A758).
Client-Rendering: renderLinks in chat.js,
createElement("a"), kein innerHTML.

### Navigations-Links im Fact-Pfad (Punkt 33, Auflagen 858-881)

Zusaetzlich zu `links` (Objekt-Referenzen) liefert
der Fact-Pfad ein eigenes Feld `nav_links` fuer
Navigations-Hinweise. Getrennt, weil `links` auf
IDs verweist und `nav_links` auf Routen.

- `ChatResponse.nav_links: list[dict]` (Default []).
- Nur bei `fact_kind == "auff_ja"` UND
  `alert.view` (RBAC im ask()-Zweig, kein Log).
- Inhalt: `{"label": "Alle Alarme ansehen",
  "href": "/alerts"}`.
- Kein Markup im answer-Text.
- Whitelist: `/alerts` exakt (`_ALLOWED_EXACT`).
  `/alerts/foo` bleibt verboten.
- Client: `renderNavLinks` in chat.js, nach
  `renderLinks`. createElement("a"), textContent,
  kein innerHTML.
- API-Antwort hat jetzt 8 Schluessel (answer, model,
  model_reason, source, denied, answer_id, links,
  nav_links).

### User-Menue-Dropdown: JS-Ausnahme (A711, A749)

Das User-Menue-Dropdown ist die einzige Ausnahme
von der Regel "kein JS in Templates". Es nutzt
<details>/<summary> + ein separates user_menu.js
fuer Klick-ausserhalb-Schliessen. Kein Inline-JS,
kein onclick=, keine Aenderung an nav.js.
Jede weitere JS-Anforderung braucht einen eigenen
Reviewer-Block.

### ProxyFix (Punkt 16a, bd7d187)

ProxyFix aktiv (x_for=1, x_proto=1, x_host=1),
weil nginx einziger vorgelagerter Proxy ist.
Login-Rate-Limit greift dadurch pro Client
statt global.

### server_name (3.6.12)

server_name akzeptiert zusaetzlich 127.0.0.1 und localhost.
Grund: lokale Diagnose ohne Host-Header-Trick.
Externe Zugriffe bleiben auf 192.168.178.117 und
security-ai.local beschraenkt. Kein Sicherheitsverlust,
weil beide Namen nur lokal aufloesen.

### default_server (3.6.12)

Ein expliziter default_server auf Port 80 und 443 liefert
return 444. Grund: unbekannter Host-Header soll kein
Info-Leak (Login-Seite) zeigen. Der 443-default_server
hat ein Zertifikat, weil TLS-Handshake vor HTTP-Routing
stattfindet.

## 17. Dashboard als administrative Oberflaeche

Das Dashboard ist nicht nur Anzeige, sondern
Steuerpult. Die Rollenverschiebung ist explizit.

- UI ruft nur Services (bestehende Regel, 11).
- CSP/CSRF/RBAC bleiben unveraendert (16).
- Aktionen werden im Human-in-the-Loop-Schema
  eingeordnet (AUTOMATIC / REVIEW /
  APPROVAL_REQUIRED).
- Kritische Aktionen laufen ausschliesslich als
  Change Request. Kein direkter Ausfuehrungspfad
  im UI.
- Der Bestaetigungsdialog ist die einzige
  Schnittstelle zwischen Bedienung und Wirkung.
  Grund: der Mensch muss vor dem Anlegen die
  Auswirkung und den Rollback sehen.
- Kurze Wege in der Bedienung: Aktionen sitzen
  auf der Detailseite und pro Zeile in Live-Listen,
  nicht in Sammel-Reitern.
- Change Request ist Pflicht bei Level 2+.

Ausnahme: Services-Status auf /system (Punkt 66).
Der SystemStatusService ruft systemctl is-active fuer
die drei eigenen security-ai-Units direkt auf
(subprocess.run, shell=False, timeout=2). Das ist die
einzige subprocess-Anwendung aus einem UI-nahen Pfad.
Die Ausnahme ist in WEB_SECURITY_CHECKLIST §N
dokumentiert und eng gefasst.

## 18. Sidebar-Baumstruktur

Die Sidebar wird Baum mit Bereichen und
Untermenues:

- Uebersicht
- Inventar (Alle, Aktive, Hauptnetz, Gastnetz,
  Detailseite)
- Alarme (Aktuell, Verlauf, Detail)
- Werkzeuge (Netzwerk-Diagnose, System, Datenbank,
  Audit, Aktionen)
- System-Status
- Verwaltung (Benutzer, Rollen, Guardrails,
  Betriebsparameter, Audit-Log, Einstellungen)

- Untermenues per details/summary oder externem JS
  (CSP-konform, kein Inline-Script).
- Hamburger-Toggle aus 3.6.11 bleibt kompatibel.

## 23. Alarm-Kanal

Der Alarm-Pfad und der Approval-Pfad nutzen
getrennte Kanaele.

### Alarm-Pfad (Punkt 81)

- Primaerer Kanal: ntfy (self-hosted, Tailscale).
- planning.py liefert PlanStep tool="notify_ntfy".
- Tool registriert in apps/security_ai/orchestrator.py
  _build_default_registry (NMAP_SCAN, READ_LOGS,
  GET_DEVICES, WHITELIST_CHECK, TELEGRAM_ALERT,
  NOTIFY_NTFY).
- Level 1 (Security Action), Sandbox-Profil
  no_network_except_ntfy.
- Fallback-Kette ntfy -> Telegram (spaeterer Ausbau).

### Approval-Pfad (Paragraph 9, unveraendert)

- orchestrator._notify_approval ruft telegram_alert_run
  DIREKT auf, NICHT ueber die Registry.
- config.yaml approval_notify.channel bleibt
  "telegram".
- Eigener Punkt 81a, falls Approval-Notify spaeter
  auch auf ntfy soll.

### Telegram bleibt optional (Punkt 76)

- telegram_alert bleibt als Tool registriert.
- Kann durch Fallback-Kette oder manuelle Konfig
  genutzt werden.

## 22. Phase-3.6.8-Erweiterungen

Siehe auch:
- docs/SECURITY_REVIEW_LOG.md — Sicherheits-
  Entscheidungen nach Thema + offene Punkte 1-11.
- docs/INCONSISTENCIES_FOUND.md — Ausgelagerte
  Inkonsistenzen (heute leer).

Diese Eintraege sind aus 3.6.8d-i entstanden und hier
zusammengefasst (kein eigener § pro Entscheidung, weil
sie sich direkt aus § 11 und § 16 ableiten).

### ServiceError / OperationError

Siehe § 11.

### ChangeService

- core/services/change_service.py.
- RBAC: change.view fuer Lesen, change.create fuer
  Anlegen.
- Audit-Kind: change_created (TOOL=change_service).
- Laengengrenzen als Modul-Konstanten (TITLE_MAX=200,
  DESCRIPTION_MAX=2000, DIFF_MAX=20000, ROLLBACK_MAX=2000,
  TEST_PLAN_MAX=2000, FILES_MAX_ENTRIES=50, FILE_PATH_MAX=500).
- Audit-Felder bei create: change_id, type, title
  (max 100), requested_by. KEIN description, diff_or_patch,
  rollback_plan, test_plan, files_affected.

### RateLimitService

- core/services/rate_limit_service.py.
- In-Memory, threading.Lock, Key = principal_name.
- WINDOW_SECONDS=60, MAX_REQUESTS=10.
- 429 + Retry-After.
- Kein Audit/Log bei Treffer.
- Single-Process heute; Multi-Worker -> gemeinsamer
  Store (Redis/DB).

### View-Projektionen (core/access/models.py)

Explizite, oeffentliche Funktionen statt Modell-to_dict:

- principal_to_view(principal) -> dict
    name, kind, role_id, is_active, has_password,
    created_at. Kein password_hash, kein row_id.
- role_to_view(role) -> dict
    name, description, created_at, permissions (sortiert).
- permission_to_view(permission) -> dict
    code, description. Kein row_id.

Begruendung: Ein Modell-to_dict wuerde reflexhaft alle
Felder mitliefern und irgendwann password_hash. Die
View-Funktion ist explizit und auditierbar.

### MIN_PASSWORD_LEN

- core/services/access_service.py, MIN_PASSWORD_LEN = 12.
- set_password prueft Laenge VOR der DB-Abfrage
  (fail closed auf Format, kein Existenz-Oracle).
- create_principal nimmt kein password_hash mehr;
  Passwort setzen ist ein eigener Schritt (set_password).

### _inject_csrf-Context-Processor

- apps/dashboard/app.py, zweiter context_processor.
- Liefert csrf_token in jedes Template.
- get_or_create ist idempotent (rotiert nicht pro
  Request); Rotation nur nach Login.
- base.html <body data-csrf-token="{{ csrf_token }}">.
- JSON-Endpoints (/api/chat) nutzen Header
  X-CSRF-Token statt Form-Feld.

### list_roles RBAC (3.6.8f)

- list_roles: role.manage ODER principal.manage.
- Begruendung: Principals anlegen erfordert
  Rollen-Kenntnis.

## 24. Rollentypen und Rolleninstanzen

Der Core definiert Rollentypen. Ein Rollentyp
ist eine Vorlage: er beschreibt, welche
Domaenen und welche Permissions in welcher
Domaene ein Principal haben darf.

Eine Rolleninstanz ist eine konkrete Rolle,
die einem Principal zugewiesen wird. Sie
entsteht aus einem Rollentyp.

Die Admin AI darf Rolleninstanzen aus
existierenden Rollentypen anlegen, wenn:
- der Rollentyp existiert,
- der Rollentyp kein Core-Admin ist,
- die Zuweisung im Rahmen der Berechtigung
  der Admin AI liegt.

Ausnahme: Core-Admins (hoechste Rolle) duerfen
nur vom Menschen angelegt werden. Die Admin AI
darf sich nicht selbst privilegieren.

Siehe docs/ADMIN_AI_SCOPE.md § 4.

## 25. Admin-AI-Scope

Die Admin AI ist Pflicht fuer die Nutzung des
Systems als Sicherheitssystem. Sie ist nicht
optional.

Sie darf:
- den Core verwalten (lesen, Endpunkte
  registrieren, Rollen aus existierenden
  Typen anlegen),
- Guardrails lesen,
- Angriffe korrelieren, Massnahmen
  vorschlagen,
- Massnahmen mit Human-Approval ausfuehren,
- die Kunden-KI konfigurieren und ueberwachen,
- Bridges registrieren und verwalten.

Sie darf nicht:
- Guardrails schreiben/aendern,
- Core-Aenderungen ohne Change Request,
- sich selbst privilegieren,
- Core-Admins anlegen,
- ohne Human-Approval kritische Aktionen
  ausfuehren.

Siehe docs/ADMIN_AI_SCOPE.md.

## 26. Ollama-Rueckbau (beschlossen)

Der lokale Ollama-Chat wird entfernt. Grund:
das lokale Modell (llama3.2:3b, qwen2.5:7b)
liefert keine brauchbaren Antworten fuer die
Komplexitaet der Aufgaben, die das System
bewaeltigen soll.

Die Intelligenz-Schicht wird von Cloud-Providern
uebernommen (siehe § 28). Der lokale Chat,
die Frage-Klassifikation (§ 14), der Auto-
Switch (§ 12) und die zugehoerigen
Komponenten (ChatService, chat_cli, Dashboard-
Chat, Kontext-Bauer, Chat-Links,
Wert-Synonyme) werden entfernt.

Das Dashboard bleibt als Basic-Verwaltung
ohne LLM. Guardrails-Aktivierung ist
Mensch-only (ueber Dashboard oder CLI).

Siehe SECURITY_REVIEW_LOG Punkt 88.

## 27. Datenklassifikation

Jede Information, die durch den Core geht,
hat eine Vertraulichkeitsstufe:

- **Oeffentlich.** Darf an jeden Cloud-Provider.
- **Intern.** Nur an Provider mit AVV
  (Auftragsverarbeitungsvertrag).
- **Vertraulich.** Nur an Provider mit AVV
  und in der EU oder gleichwertig.
- **Streng vertraulich.** Nur lokal oder
  gar nicht. Kein Cloud-Provider.

Die Firma entscheidet pro Installation,
welche Stufe welchen Provider nutzen darf.

Der Core filtert jede Anfrage an die Admin AI
nach dieser Klassifikation. Was nicht raus
darf, geht nicht raus.

Die Klassifikation ist Datenpflege, nicht
Code. Sie kann im Dashboard angepasst werden
(vom Menschen) oder durch Change Request.

## 28. Cloud-Provider austauschbar

Die LLM-Anbieter sind austauschbare Module.
Der Core kennt nur das LLMProvider-Interface.
Welche Anbieter konfiguriert sind, steht in
einer Provider-Registry.

Vorgesehene Anbieter (nicht abschliessend):
- Azure OpenAI (deutscher Standard fuer
  Firmen).
- Anthropic (Claude).
- OpenAI (GPT).
- DeepSeek.
- Microsoft Copilot.

Ein neuer Anbieter ist ein Eintrag in der
Provider-Registry und eine Implementierung
des LLMProvider-Interface. Kein Umbau der
Architektur.

Der Core routet Anfragen an den passenden
Provider je nach:
- Datenklassifikation (§ 27),
- Verfuegbarkeit,
- Konfiguration.

## 29. Core pro Firma

Jede Firma installiert ihren eigenen Core.
Keine Mandantenfaehigkeit auf einer
gemeinsamen Installation.

Konsequenzen:
- Keine Mandanten-Spalte in Tabellen.
- Keine Trennung zwischen Kunden auf
  Anwendungsebene.
- Eigene Datenbank pro Firma.
- Eigene Zertifikate pro Firma.
- Eigene Rollen, Domaenen, Endpunkte
  pro Firma.
- Eigene Admin AI (Cloud der Firma).
- Eigene Kunden-KI (Cloud der Firma).

Foederation zwischen Installationen ist
optional (siehe docs/PROTOCOL.md). Eine
Admin AI kann mehrere Cores ihrer Firma
korrelieren. Kein Core sieht einen anderen.

Der Core laeuft autark. Er funktioniert auch
ohne Admin AI und ohne Kunden-KI. Was fehlt,
ist die Intelligenz-Schicht, nicht die
Sicherheitsbasis.
