# ADR-0002: Audit-Nomenklatur

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §2

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
