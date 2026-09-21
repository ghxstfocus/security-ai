-- 0004_change_requests.sql
-- Change Requests: strukturierte Aenderungsantraege.
--
-- SQLite ist die Quelle der Wahrheit.
-- JSON-Dateien in changes/ sind Export (fuer Foederation, Signierung,
-- Git-Versionierung). Siehe core/changes/parser.py.
--
-- change_id-Format: CHG-YYYY-NNNNN (jahresweise, 5-stellig).
-- status-Werte (Enum ChangeStatus): draft, testing, pending_review,
-- approved, deployed, rolled_back, rejected.
-- type-Werte (Enum ChangeType): config_change, code_change,
-- policy_change, firewall_change, device_whitelist_change.
-- status und type sind TEXT ohne CHECK (Konvention im Code, nicht
-- in der DB - konsistent zu device_history.event_type und
-- approvals.status).

CREATE TABLE IF NOT EXISTS change_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    change_id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    type TEXT NOT NULL,
    diff_or_patch TEXT,
    files_affected TEXT,
    rollback_plan TEXT,
    test_plan TEXT,
    related_approval_id TEXT,
    related_event_id TEXT,
    risk_category TEXT,
    risk_score REAL,
    decided_at TEXT,
    decided_by TEXT,
    decision_reason TEXT,
    deployed_at TEXT,
    rolled_back_at TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_change_requests_status
    ON change_requests(status);
CREATE INDEX IF NOT EXISTS idx_change_requests_change_id
    ON change_requests(change_id);
CREATE INDEX IF NOT EXISTS idx_change_requests_type
    ON change_requests(type);
