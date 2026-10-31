# ADR-0007: Change Requests (Phase 4b)

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §7

---

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
