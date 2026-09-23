# Phasen

Uebersicht aller Phasen mit Status.
Details in `docs/DESIGN_DECISIONS.md` und den jeweiligen Modulen.

Legende: [x] abgeschlossen, [~] in Arbeit, [ ] geplant.

## Phase 1 — Harness + Docs  [x]

7 Docs, 7 Kernmodule: events, audit/writer,
permissions/levels, tool_registry/{tool,registry},
agent_loop/{loop,model}. 12 Tests.

## Phase 2 — Detection  [x]

core/detection/rule_base.py, engine.py.
Regeln unknown_device + port_scan.
detection/rules.yaml.

## Phase 2b — Inventory + Risk + Orchestrator + Audit  [x]

Inventory in SQLite (data/migrations/0002, devices,
device_history, whitelisted_devices).
core/inventory/{device,repository,whitelist}.py.
Risk Engine (core/risk/{models,engine}.py + rules.yaml).
apps/security_ai/orchestrator.py mit process(event) und
Audit-Eintraegen.

## Phase 3.1 — Policy Engine  [x]

harness/policy_engine/{policy,engine}.py, policies/tools.yaml.
Decision ALLOWED / APPROVAL_REQUIRED / FORBIDDEN, strengste
gewinnt. Globale Pruefer no_shell_chars, no_path_traversal,
no_null_bytes.

## Phase 3.2 — 5 Tools  [x]

tools/{nmap_scan,read_logs,get_devices,whitelist_check,
telegram_alert}.py.

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

data/migrations/0003_approvals.sql, 0004_change_requests.sql.
core/approval/, core/changes/.
scripts/approvals_cli.py, scripts/changes_cli.py.
harness/versioning/applier.py (Stub).
harness/approval/queue.py, AgentLoop mit approval_queue.
_notify_approval (Telegram, fail open).

## Phase 3.5 — Lokale KI  [x]

Fertig:
- core/config.py (.env-Loader)
- harness/llm/ (OllamaClient, LLMRequest/Response,
  Fehlerklassen LLMError / LLMUnavailable / LLMTimeout)
- harness/context/ (ContextBundle, ContextBuilder, Redaction)
- core/access/ (RBAC: Principal, Role, Permission, Checker)
- core/services/access_service.py
- apps/security_ai/chat.py (ChatService mit chat_query,
  chat_access_denied, Detail-Pfad, Modellwahl)
- scripts/init_db.py (DB + cli-admin)
- scripts/chat_cli.py (--whoami / --question / --detail / --model)
- .env.example, .gitignore
- Ollama (llama3.2:3b Default, qwen2.5:7b Large)
- Erster echter Chat erfolgreich

Offen: keine funktionalen Blocker.

## Phase 3.5.5 — Service-Refactor  [x]

AccessChecker mit Repo-Injection (principal_repo, role_repo,
permission_repo) + from_conn-Convenience + check-Alias.
role_of -> str | None, permissions_of -> frozenset (leer bei
unbekannt/inaktiv). AccessService und ChatService mit DI.
chat_cli.py verdrahtet Repos + Checker.
tests/unit/test_access.py.

## Phase 3.5.6 — Kontext-Anschluss  [x]

Commits: 9d4dead, 8d345e6, 7c65f51, c07ea4e

- core/reporting/audit_reader.py — risk_assessments aus JSONL.
- core/reporting/inventory_snapshot.py — Aggregation.
- _build_prompt zeigt Kategorien, Regeln, Scores, Zeitraum.
- chat_cli laedt Kontext und uebergibt an ChatService.

## Phase 3.5.7 — Auto-Switch zu grossem Modell  [x]

Commits: 6ba7b26, 1b2ca83, c857e55, f414626, 7500825

- System-Prompt unterscheidet Konzept- und Zustandsfragen.
- no_context-Pfad: vage Zustandsfrage ohne Kontext -> ehrliche
  Antwort.
- Kategorien-Glossar und WICHTIG-Hinweis im Prompt.
- Auto-Switch: Zustandsfrage + CONFIRMED/SECURITY_ALERT ->
  qwen2.5:7b.
- ChatResponse.model_reason fuer Transparenz.

## Phase 3.5.7a — Timeouts + --no-auto-large  [x]

Commits: 35d34ed

- Modellabhaengige Timeouts (3B: 30s, 7B: 180s, sonst 60s).
- --no-auto-large als Opt-out.
- CLI zeigt [Modell: <name> -- <reason>].

## Phase 3.5.7b — Warnung vor LLM  [x]

Commits: 73278e3

- ChatService.ask(on_model_selected=...) Callback.
- Warnung kommt VOR dem LLM-Aufruf.

## Phase 3.5.8 — Frage-Klassifikation  [x]

Commits: 47ccd04

- fact/concept/interpretation via Regex.
- fact-Pfad ist deterministisch (kein LLM).
- Detail-Pfad hat Vorrang vor fact.
- no_context nur fuer interpretation.
- _answer_fact fuer "Gab es Auffaelligkeiten?", "Welche
  Kategorien?", "Wie viele?".

## Phase 3.5.9 — Sanity-Check + Retry  [x]

Commits: cd16bf6, 93354e4, d266bff

- _answer_contradicts_context erkennt Denial UND Underreporting.
- Retry mit qwen2.5:7b bei Widerspruch.
- source="llm_retry", Audit chat_answer_contradicts_context.
- Nur bei Interpretation (nicht concept).
- Nicht abschaltbar durch --no-auto-large (Sicherheitsschicht).
- Prompt-Hinweis "Du MUSST die CONFIRMED-Zahlen nennen".
- CLI-Warnung bei --no-auto-large.

## Phase 3.5.5+ — optional  [ ]

Principal-Objekte als API-Rueckgabe, assign_role, strengere
Service-Trennung. Aktuell nicht noetig.

## Phase 3.6 — Web-Dashboard  [~]

Flask-App in apps/dashboard/. Login ueber principals.
Bereiche: Dashboard, Inventar, Alarme, Approvals, Changes,
Chat, Benutzerverwaltung, Rollenverwaltung, Audit,
Einstellungen. Ziel: Browser als primaeres Interface.

## Phase 3.6.1 — Session-Modell + Repository  [x]

Commits: d3b6689, 84511c4, cd6eda4, 9fc4a83,
         0a0c5b2, cf0d30c

- Migration 0006 (sessions, login_attempts).
- Session-Dataclass in core/access/models.py.
- SessionRepository + LoginAttemptRepository.
- AccessService(session_repo Pflicht).

## Phase 3.6.2 — get_secret_key  [x]

Commits: 4b4a82b

- core/config.py::get_secret_key.
- ConfigError (fail closed).
- Byte-Laenge, nicht Zeichen-Laenge.

## Phase 3.6.3 — AccessService.set_password  [x]

Commits: 644993a

- set_password (RBAC + Session-Invalidierung).
- revoke_all_for_principal bei Passwort-Aenderung.
- Auflage 14.

## Phase 3.6.4 — AuditReaderService  [x]

Commits: 4a4e2ab

- core/services/audit_reader_service.py.
- RBAC (audit.read), Input-Validierung.
- Nur Lesen.

## Phase 3.6.5 — Flask-App-Factory + RBAC  [x]

Commits: e8ff4d2

- apps/dashboard/app.py + decorators.py.
- create_app + before_request + Sicherheitsnetz.
- Errorhandler (403 + 500 generisch).
- 13 Tests in test_dashboard_app.py.
- Auflagen 53-74, 106, 108.
- venv-Umstellung (pyproject-konform) parallel.

## Phase 3.6.6 — Login + Logout + CSRF + Rate-Limit + Audit  [x]

Commit: c2e5e9d, b3558db

Notizen:

- Login-Flow: CSRF, Rate-Limit pro IP,
  User-Enumeration-Schutz, Session-Fixation-
  Schutz, Audit (login_success, login_failed,
  login_locked, logout).
- Routen: /login, /logout, /whoami.
- Test 7 (test_public_route_no_redirect) auf
  reale /login-Route umstellen.
- Kategorie 3.
- Details: docs/WEB_SECURITY_CHECKLIST.md
  Abschnitt A, B, C, I.

## Phase 3.6.7a — Static (CSS, JS, img)  [x]

Commit: 57081d3

- 9 Dateien: 6 CSS, 1 JS, 2 SVG.
- Kein CDN, keine externen Fonts.
- SVG-Favicon.

## Phase 3.6.7b — base.html + Partials + CSP  [x]

Commit: d6d8e95

- base.html + 6 Partials + _helpers.html.
- CSP-Header in after_request.
- Security-Header (X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy,
  Permissions-Policy).
- XSS-Tests (test_templates_xss.py).

## Phase 3.6.7c — login.html als Template  [x]

Commit: 8b75f0a

- login.html (standalone, kein extends).
- login_form rendert Template.
- html.escape entfernt (Jinja escaped).

## Phase 3.6.7d — index.html + Route /  [x]

Commit: 63f6988

- routes_index.py mit @require_permission
  ("device.read").
- index.html (extends base).
- stat_card.html als Makro.
- 4 Stat-Cards mit Platzhalter em-dash.

## Phase 3.6.7e — CSP-Test + PHASES  [x]

Commit: 06f6f48, 3a3f926

- test_csp_all_directives_present.
- Diese Notizen.

## Phase 3.6.8 — Seiten mit echten Daten  [~]

Ziel: die in der Sidebar verlinkten Seiten mit
Inhalten fuellen (Route + Service + Template +
Tests). Pro Seite ein Unterschritt.

Fertig:

Commits: b82f253, 8692eb6, 97dbde9, 36f65a1,
         c7791c9, 2d4b437, a2c4dc1, 8d43034, 6ae8bd5,
         25d9614

- Migration 0007: alert.view.
- ServiceError-Basis + AuditReaderServiceError.
- AuditReaderService.list_recent_assessments
  (RBAC alert.view, limit 1..1000).
- UI: Sidebar + Stat-Cards bedingt
  (context_processor _inject_nav_permissions,
  data-nav, data-card).

Offen:

- [x] 3.6.8a Inventar       (/inventory,
                             device.read)
      Commit: 2d4b437.
- [x] 3.6.8b Alarme         (/alerts,
                             alert.view)
      Commit: 6ae8bd5.
      Fix:    8d43034 (AuditReaderService base_dir).
- [x] 3.6.8c Approvals      (/approvals,
                             approval.view
                             + approval.decide)
      Commit: 25d9614.
- [ ] 3.6.8d Changes        (/changes,
                             change.view
                             + change.create)
- [ ] 3.6.8e Chat           (/chat + /api/chat,
                             chat.ask)
- [ ] 3.6.8f Benutzer       (/users,
                             principal.manage)
- [ ] 3.6.8g Rollen         (/roles,
                             role.manage)
- [ ] 3.6.8h Audit          (/audit, audit.read)
- [ ] 3.6.8i Einstellungen  (/settings,
                             role.manage)

Kategorie 3 fuer alle (Routes + RBAC + Templates).

Nach 3.6.8i (Optik, sobald Struktur + Daten stehen):

- [ ] 3.6.10 Responsive-Feinschliff (Kategorie 1, CSS-only)
      .table-Verhalten auf <700px, .topbar, .card,
      .form-input. Keine Template-Aenderung.
- [ ] 3.6.11 Hamburger-Navigation (Kategorie 3)
      Button in topbar.html, Toggle in static/js/nav.js
      (extern, addEventListener, kein onclick=, kein
      Inline-<script>, keine style="..."), CSP-konform.

## Phase 3.8 — Host-Scanner / Netzwerk-Discovery  [ ]

Ziel: das gesamte Heimnetz beobachten, nicht nur den
Container. Scapy-Sniffer laeuft auf dem Proxmox-Host
(host_scanner.py auf vmbr0), nicht in einem LXC.

Siehe docs/ARCHITECTURE.md § 5 (Deployment-Topologie),
docs/DEPLOYMENT.md ("Host: host_scanner auf pve").

Regeln (aus ARCHITECTURE § 5):
- LXC 1 (security-ai) hat kein CAP_NET_RAW.
- LXC 2 (security-tools) hat CAP_NET_RAW, aber kein Internet.
- Host-Scanner laeuft ausserhalb der Container.

Status: noch nicht implementiert. Aktuell nur nmap-Scan
im Container gegen Test-Ziele (Phase 3.4).

## Phase 5 — Admin AI  [ ]

Optional, Cloud-basiert, ueber MCP. Setzt lokale KI
(Phase 3.5) voraus. Foederation ueber core/protocol/.
