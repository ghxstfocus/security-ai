# Phasen

Uebersicht aller Phasen mit Status und wichtigsten Commits.
Details in `docs/DESIGN_DECISIONS.md` und den jeweiligen
Modulen.

Legende: [x] abgeschlossen, [~] in Arbeit, [ ] geplant.

## Phase 1 — Harness + Docs  [x]

7 Docs, 7 Kernmodule: events, audit/writer,
permissions/levels, tool_registry/{tool,registry},
agent_loop/{loop,model}. 12 Tests (test_agent_loop.py).

## Phase 2 — Detection  [x]

core/detection/rule_base.py, engine.py,
Regeln unknown_device + port_scan, detection/rules.yaml.

## Phase 2b — Inventory + Risk + Orchestrator + Audit  [x]

Inventory in SQLite (data/migrations/0002, devices,
device_history, whitelisted_devices),
core/inventory/{device,repository,whitelist}.py.
Risk Engine (core/risk/{models,engine}.py + rules.yaml).
apps/security_ai/orchestrator.py mit process(event)
und Audit-Eintraegen.

## Phase 3.1 — Policy Engine  [x]

harness/policy_engine/{policy,engine}.py,
policies/tools.yaml. Decision ALLOWED / APPROVAL_REQUIRED /
FORBIDDEN, strengste gewinnt. Globale Pruefer
(no_shell_chars, no_path_traversal, no_null_bytes).

## Phase 3.2 — 5 Tools  [x]

tools/nmap_scan.py, read_logs.py, get_devices.py,
whitelist_check.py, telegram_alert.py.

## Phase 3.3 — Orchestrator + AgentLoop + Integration  [x]

apps/security_ai/planning.py (SecurityPlanModel),
apps/security_ai/config.yaml, AgentLoop mit Policy-Check
vor Argument-Validierung.

## Phase 3.4 — Echter nmap-Aufruf  [x]

tools/nmap_scan.py v0.2.0: subprocess mit Sandbox
(Timeout, kein Shell, Argument-Whitelist, Ziel-Whitelist via
ipaddress, XML-Parsing mit -oX -). Integrationstest
tests/integration/test_nmap_real.py (skipif kein nmap).

## Phase 4.1-4.3 — Approval + Change Requests  [x]

data/migrations/0003_approvals.sql + 0004_change_requests.sql.
core/approval/, core/changes/. core/services/.
scripts/approvals_cli.py, scripts/changes_cli.py.
harness/versioning/applier.py (Stub).
harness/approval/queue.py, AgentLoop mit approval_queue.
_notify_approval (Telegram, fail open).

## Phase 3.5 — Lokale KI  [~]

Fertig:
- core/config.py (.env-Loader)
- harness/llm/ (OllamaClient, LLMRequest/Response,
  Fehlerklassen LLMError/LLMUnavailable/LLMTimeout)
- harness/context/ (ContextBundle, ContextBuilder, Redaction)
- core/access/ (RBAC: Principal, Role, Permission, Checker)
- core/services/access_service.py
- apps/security_ai/chat.py (ChatService mit chat_query,
  chat_access_denied, Detail-Pfad, Modellwahl)
- scripts/init_db.py (DB + cli-admin)
- scripts/chat_cli.py (--whoami/--question/--detail/--model)
- .env.example, .gitignore
- Ollama laeuft (llama3.2:3b Default, qwen2.5:7b Large)
- Erster echter Chat erfolgreich

Offen:
- keine offenen Blocker fuer Phase 3.5 (funktional fertig)

## Phase 3.5.5 — Service-Refactor  [x]

AccessChecker mit Repo-Injection (principal_repo, role_repo,
permission_repo) + from_conn-Convenience + check-Alias.
role_of -> str | None, permissions_of -> frozenset
(leer bei unbekannt/inaktiv).
AccessService und ChatService mit DI.
chat_cli.py verdrahtet Repos + Checker.
tests/unit/test_access.py (19 Tests).

## Phase 3.5.5+ — optional  [ ]

Principal-Objekte als API-Rueckgabe, assign_role,
strengere Service-Trennung. Aktuell nicht noetig.

## Phase 3.6 — Web-Dashboard  [ ]

Flask-App in apps/dashboard/. Login ueber principals.
Bereiche: Dashboard, Inventar, Alarme, Approvals, Changes,
Chat, Benutzerverwaltung, Rollenverwaltung, Audit,
Einstellungen. Ziel: Browser als primaeres Interface.

## Phase 5 — Admin AI  [ ]

Optional, Cloud-basiert, ueber MCP. Setzt lokale KI
(Phase 3.5) voraus. Foederation ueber core/protocol/.
