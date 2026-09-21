-- 0003_approvals.sql
-- Approval-Queue: Freigabe-Anfragen fuer Tool-Aufrufe mit
-- Policy-Entscheidung APPROVAL_REQUIRED.
--
-- DB ist die Quelle der Wahrheit, nicht Telegram.
-- Audit-Log dokumentiert jede Anfrage und jede Entscheidung.

CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    args_json TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    reason TEXT,
    risk_category TEXT,
    risk_score REAL,
    event_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    decided_at TEXT,
    decided_by TEXT,
    decision_reason TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approvals_status
    ON approvals(status);
CREATE INDEX IF NOT EXISTS idx_approvals_request_id
    ON approvals(request_id);
