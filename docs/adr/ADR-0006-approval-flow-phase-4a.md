# ADR-0006: Approval-Flow (Phase 4a)

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §6

---

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
