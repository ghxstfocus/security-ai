# Design-Entscheidungen

> Dieses Dokument sammelt die verbindlichen Entscheidungen, die
> im Verlauf des Projekts getroffen wurden. Es ist die erste
> Adresse bei Unklarheiten.
>
> Stand: Phase 3.3 abgeschlossen.

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

## 4. Format und Prozess

- Keine Umlaute in Code-Bloecken (oe, ue, ae, ss).
- Kein sed auf Python-Code. Patches per Python-Skript
  (Path.read_text/replace/write_text).
- Nach jedem Schreiben: wc -l, py_compile, Test, git commit.
- Bei langen Dateien zwei oder drei Bloecke.
- Bei Fehlern: kurze Ursache, dann Fix, keine langen Vorreden.

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

### ChatService

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
