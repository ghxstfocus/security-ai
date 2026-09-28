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

## Phase 3.6.8 — Seiten mit echten Daten  [x]

Ziel: die in der Sidebar verlinkten Seiten mit
Inhalten fuellen (Route + Service + Template +
Tests). Pro Seite ein Unterschritt.

Fertig:

Commits: b82f253, 8692eb6, 97dbde9, 36f65a1,
         c7791c9, 2d4b437, a2c4dc1, 8d43034, 6ae8bd5,
         25d9614, 29535ce, 148b434, 1f16127, 9c3accb,
         fbfafc6, 14cccd5

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
- [x] 3.6.8d Changes        (/changes,
                             change.view
                             + change.create)
      Commit: 29535ce.
- [x] 3.6.8e Chat           (/chat + /api/chat,
                             chat.ask)
      Commit: 148b434.
      Inkl.: RateLimitService + CSRF-Header (X-CSRF-Token)
             + _inject_csrf-Context-Processor.
- [x] 3.6.8f Benutzer       (/users,
                             principal.manage)
      Commit: 1f16127.
      Inkl.: principal_to_view, MIN_PASSWORD_LEN=12,
             list_roles mit principal.manage.
- [x] 3.6.8g Rollen         (/roles,
                             role.manage)
      Commit: 9c3accb.
      Inkl.: role_to_view, permission_to_view,
             assign/revoke, self-critical Warnung (A184).
- [x] 3.6.8h Audit          (/audit, audit.read)
      Commit: fbfafc6.
      Inkl.: Tag-Filter (UTC heute default), Detail
             mit formatiertem details, kein read_all.
- [x] 3.6.8i Einstellungen  (/settings,
                             role.manage)
      Commit: 14cccd5.
      Inkl.: read-only Konfigurationsanzeige, kein
             SECRET_KEY, kein os.environ-Dump.

Kategorie 3 fuer alle (Routes + RBAC + Templates).

Nach 3.6.8i (Optik, sobald Struktur + Daten stehen):

- [x] 3.6.10 Responsive-Feinschliff (Kategorie 1, CSS-only)  -- erledigt in 064ea5b
      .table-Verhalten auf <700px, .topbar, .card,
      .form-input. Keine Template-Aenderung.
- [x] 3.6.11 Hamburger-Navigation (Kategorie 3)  -- erledigt in bc058a1
      Button in topbar.html, Toggle in static/js/nav.js
      (extern, addEventListener, kein onclick=, kein
      Inline-<script>, keine style="..."), CSP-konform.

## Punkt 26 — security_ai-Startpfad  [ ]

Ziel: __main__.py, systemd-Unit (analog
security-ai-dashboard), check_schema_version.
Kategorie 3, eigener Block. Naechster Block
(nach Core-Abschluss).

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

## Phase 3.6.11 — Hamburger-Navigation  [x]

Ziel: Sidebar auf <=700px ausblenden und per Button
in der Topbar ein-/ausblenden. Der Sidebar-Overflow
("tare"-Fragment) wird damit behoben.

Kategorie 3 (CSP-naehe, externes JS, addEventListener).
Reviewer-Freigabe: Auflagen 346-364 (Reviewer-Chat,
2026-09-24).

Kurzfassung Auflagen:
- 346: erlaubte Dateien (base.html, topbar.html,
  sidebar.html, nav.js, layout.css, components.css,
  test_dashboard_nav.py).
- 347: verboten (app.py, CSP-Header, Cookie-Flags,
  main.js, chat.js).
- 348: Default >700px sichtbar, <=700px versteckt.
- 349: Overlay-Toggle, kein Layout-Wechsel.
- 350: kein localStorage.
- 351: SVG extern (static/img/hamburger.svg).
- 352: max. 150ms Transition auf transform.
- 353: nav.js extern, IIFE, kein eval/innerHTML/onclick.
- 354: Button-Markup mit id=nav-toggle, aria.
- 355: Sidebar per visibility, kein aria-hidden.
- 356: Fokus-Handling, Esc schliesst.
- 357-360: Tests (Button, nav.js, CSP unveraendert).
- 361: Sichtpruefung 1920/1100/700/400px + S25.
- 362: Reihenfolge 3.6.11 vor 3.6.13/3.6.14.
- 363: offene Punkte 12-15 parallel.
- 364: (Nummersprung, siehe Reviewer-Chat).

Offen: "tare"-Effekt-Diagnose vor Baubeginn
(Browser DevTools auf /alerts 400px).

Erledigt in bc058a1. Auflagen 346-364 umgesetzt:
nav.js extern (IIFE, addEventListener, kein eval/
innerHTML/onclick, kein localStorage), nav-toggle in
topbar.html (id, aria-label, aria-expanded,
aria-controls), hamburger.svg extern, Fokus-Handling
und Esc schliesst (nav.js), nav.js in base.html geladen.
Sichtpruefung 1920/1100/700/400px bestaetigt.

## Phase 3.6.12 — HTTPS fuer das Dashboard  [x]

Ziel: Login und alle Dashboard-Routen ueber HTTPS
erreichbar. Heute blockiert SESSION_COOKIE_SECURE=True
jeden Login ueber HTTP (Browser schickt die Session-
Cookie nicht zurueck -> CSRF-Check schlaegt fehl ->
400 "Ungueltige Anfrage").

Optionen:
- Self-signed Zertifikat + Flask ssl_context.
- Reverse-Proxy (nginx/caddy) mit TLS vor Flask.

Wenn TLS steht: HSTS-Header, Cookie-Flags pruefen
bleiben unveraendert, Testmatrix fuer HTTPS ergaenzen.

Kategorie 3 (TLS, Auth, Cookie-Flags).
Siehe docs/SECURITY_REVIEW_LOG.md offener Punkt 10.

Erledigt in dieser Session (Commits afb4eb2 und 37ae99d):
- nginx 1.22.1 aus bookworm installiert, eigene CA +
  Server-Zertifikat (SAN: security-ai.local, security-ai,
  192.168.178.117, 127.0.0.1).
- apps/dashboard/app.py: if __name__ == "__main__"-Block
  mit host=127.0.0.1, port=5000, debug=False.
- deploy/systemd/security-ai-dashboard.service mit Hardening
  (User=security-ai, ProtectSystem=strict, NoNewPrivileges).
- deploy/nginx/security-ai.conf mit TLS 1.2/1.3, HSTS,
  default_server return 444, CSP aus Flask unveraendert.
- docs/DEPLOYMENT.md §3c (CA, Zertifikat, nginx-Config,
  systemd-Units, Fail closed, Checkliste §L), §4.2/§4.4/§7/§10
  korrigiert, WEB_SECURITY_CHECKLIST §L auf [x].
- Login-Test ueber HTTPS: 302 (Redirect), kein 500er.
- Offene Punkte 12-15 in SECURITY_REVIEW_LOG ergaenzt.

## Phase 3.6.13 — Systemvoraussetzungen dokumentieren  [x]

Ziel: eine vollstaendige Liste der Systempakete und
Python-Abhaengigkeiten, die fuer den Betrieb von CT102
noetig sind. Bestandsaufnahme: dpkg -l, Import-Abgleich
ueber apps/core/harness/tools/scripts, Abgleich mit
pyproject.toml und DEPLOYMENT.md §3a/§3b/§3c. Ergebnis als
neue Sektion in docs/DEPLOYMENT.md oder eigene Datei
docs/REQUIREMENTS.md. Kategorie 2 (Doku + Bestandsaufnahme).

Anlass: 3.6.12 installiert nginx als Systempaket. Aktuell
sind die Abhaengigkeiten ueber pyproject.toml, DEPLOYMENT.md
§2.4/§3a/§3b/§3c verstreut. Ein Neuaufbau braucht die
zentrale Liste.

## Phase 3.6.14 — UI-Politur Alerts-Tabelle  [x]

Ziel: die Alert-Tabelle lesbarer machen. Aus der
Sichtpruefung 3.6.10 ergaben sich drei Befunde, die
nicht CSS-only loesbar sind:

1. Spaltenueberschriften sind technisch:
   - Score -> was fuer ein Score?
   - Regel -> was fuer eine Regel?
   - Event-ID -> technisch.
   Vorschlag: Erkennungsregel, Bewertung, Ereignis-ID.

2. Datumsformat ist ISO 8601 mit Mikrosekunden
   (2026-09-23T21:17:00.072011+00:00).
   Vorschlag: 23.09.26 21:17 (kompakt).
   Zu klaeren: UTC belassen oder lokale Zeit.

3. Score-Darstellung ist Fliesskomma-Artefakt
   (0.9500000000000001).
   Vorschlag: Label gross + Zahl klein darunter:
       KRITISCH
       0.95
   Labels abgeleitet aus existierenden Kategorien
   (core/risk/models.py):
       EVENT          -> Info
       ANOMALY        -> Hinweis
       SUSPICION      -> Warnung
       SECURITY_ALERT -> Alarm
       CONFIRMED      -> Kritisch
   Schwellwerte sind bereits definiert
   (DEFAULT_THRESHOLDS: 0.2 / 0.4 / 0.6 / 0.8).

Zusaetzlich: pro Tabelle eine Klasse
(table-alerts, table-inventory, ...) zur Definition
der Hardfacts fuer <500px. Ersetzt die globale
nth-child(n+4)-Regel aus 3.6.10.

Kategorie 2 (Template-Aenderungen, Tests).
Kein RBAC/CSP/CSRF betroffen.
Reihenfolge: nach 3.6.11.

Abschluss (2026-09-25, Commit bba4ac7):
- Spaltenueberschriften umbenannt (Auflage 422).
- Datumsformat via format_ts, UTC (Auflage 423).
- Badge-Text via format_score_label (Auflage 424).
- Score via format_score, zwei Stellen (Auflage 425).
- Kategorie und Score in einer Bewertung-Spalte
  (Variante B, Reviewer-Entscheidung).
- .badge bekommt white-space: nowrap (F2).
- filters.py neu (format_ts, format_score_label,
  format_score), in create_app registriert
  (Auflage 426, 427).
- tests/unit/test_filters.py neu (21 Tests,
  unittest.TestCase, Auflage 426).
- tests/unit/test_dashboard_alerts.py an die neue
  Badge-Semantik angepasst (Auflagen 434-440).
- partials/alert_row.html entfernt (verwaist,
  Auflagen 420/421).
- Pro-Tabelle-Klassen als offener Punkt 19 notiert
  (Auflage 419), eigener Folgeschritt.

## Phase 3.6.15a — Migrations-Tracking + Deployment-Schritt  [x]

Ziel: das Migrations-Tracking reparieren (offener
Punkt 15 in SECURITY_REVIEW_LOG), einen
Deployment-Schritt einfuehren, und den App-Start
fail-closed gegen eine veraltete DB absichern.
Ausloeser: Login-500er am 2026-09-23/24 (fehlende
Tabellen sessions und login_attempts aus Migration
0006, weil 0003-0007 sich nicht in schema_migrations
eintrugen).

Fix A+B (Commit ce25660):
- apply_migrations traegt pro Datei Version in
  schema_migrations ein (INSERT OR IGNORE) und
  ueberspringt bereits angewandte Versionen.
- Dateiname-Parser strikt vierstellig
  (^\d{4}_), 0000 erlaubt, 10000 abgelehnt,
  init.sql uebersprungen (Auflage 402).
- ensure_schema_migrations ist die einzige Quelle
  fuer das Tracking-Schema (Auflage 401).
- Tests: 13 neue in tests/unit/test_migrations.py
  (Auflagen 393, 402, 394).

Fix D (Commit 1cedb26):
- check_schema_version prueft MAX(version) gegen
  hoechste Datei-Version in data/migrations/
  (DB < Datei -> SchemaVersionError, DB > Datei ->
  logger.warning, DB == Datei -> still,
  fehlende Tabelle -> SchemaVersionError mit
  diagnostischer Meldung, Auflage 403).
- create_app bekommt Keyword-only Parameter
  check_schema: bool = True (Auflage 406).
- build_dashboard_app setzt check_schema=False
  (Auflage 407).
- Tests: 5 neue in test_migrations.py, 2 neue in
  test_dashboard_app.py (Auflage 408).

Fix C (Commit dd10214):
- Repo-Vorlage deploy/systemd/security-ai-dashboard.service
  mit ExecStartPre: init_db.py --no-principal
  vor App-Start (Auflagen 395, 396, 414, 416).
- docs/DEPLOYMENT.md neuer Abschnitt 3e
  (Migrationspflicht): Reihenfolge ExecStartPre ->
  App-Start, copy-paste-faehiger cp-Befehl,
  Verifikations-SQL, Hinweis Version 1, Hinweis
  Downgrade (Auflagen 400, 410, 411, 417, 409).
- docs/SECURITY_REVIEW_LOG.md Punkt 15 um
  Erledigt-Vermerk ergaenzt (Referenz bleibt).
  Neuer Punkt 17 (check_schema_version auch beim
  security_ai-Start, Auflage 398). Neuer Punkt 18
  (DEPLOYMENT 1 Topologie-Drift, Auflage 413).

Reihenfolge: nach 3.6.13, vor 3.6.15b.

## Phase 3.6.15b — Audit-Rechte fail closed + Test-Isolation  [x]

Ziel: AuditWriter fail closed bei inkonsistenten
Tagesdateien (Modus, Owner). Service-Start prueft
audit-logs/. Ausloeser: Punkte 12/13/14 in
SECURITY_REVIEW_LOG (Vorfall 23./24.09. und erneut
25.09. 17:06: Datei 644 root:root).

Fix 13 Option B (harness/audit/writer.py):
- write() prueft Modus existierender Tagesdateien
  vor dem Schreiben. Modus != 0o640 -> AuditWriteError,
  kein Silent Repair (Auflagen 471, 472).
- Neue Dateien: os.open(mode=0o640) + os.chmod.
- Kein Owner-Check in write() (Auflage 467).
- Race-Schutz FileNotFoundError zwischen exists()
  und stat() (Auflage 471).

Fix 14 (harness/audit/writer.py):
- Modul-Funktion check_audit_logs(base_dir,
  expected_owner). Prueft alle *.jsonl auf Modus
  0o640 und Owner per pwd.getpwuid (kein UID-
  Vergleich, Auflage 464).
- Neue Exception AuditDirInconsistentError
  (Subklasse von AuditError, Auflage 463).

create_app (apps/dashboard/app.py):
- Neuer Keyword-Parameter check_audit: bool = True
  (Auflage F4).
- Aufruf check_audit_logs vor check_schema_version
  (Auflage F5). expected_owner per
  pwd.getpwuid(os.getuid()).pw_name.
- build_dashboard_app (Testhelfer) setzt
  check_audit=False.

Fix A (Test-Isolation):
- tests/integration/test_orchestrator.py
  OrchestratorTests.setUp schrieb bisher in die
  echte audit-logs/. Fix 13 Option B hat das
  aufgedeckt (12 Tests rot). setUp nutzt jetzt
  audit_base_dir=self.audit_dir im tmp-Verzeichnis,
  konsistent zu den anderen drei setUp-Bloecken
  (Auflage 478).

Fix C (Rueckfall-Schutz):
- Neuer Test test_setup_isolation in
  OrchestratorTests. Snapshot der echten
  audit-logs/ vor/nach einem process()-Aufruf,
  erwartet identisch (Auflage 480). Skippt, wenn
  audit-logs/ fehlen.

Tests: 9 neue in tests/unit/test_audit_writer_rechte.py,
1 neuer Integrationstest. Commit a3589db.

Betriebsakt (offen, Mensch entscheidet):
- audit-logs/2026-09-25.jsonl (644 root:root) bleibt
  unangetastet. Rechte-Korrektur (chown + chmod) oder
  Umbenennung als Vorfall-Nachweis (Auflagen 469/482).

Reihenfolge: nach 3.6.15a, vor 3.6.15c.

## Phase 3.6.15c — Fehlerklassen-Trennung (Punkte 5/6)  [x]

Ziel: Format- und Betriebsfehler in den Kern-Services
trennen (Punkte 5 und 6 in SECURITY_REVIEW_LOG).
Vorbild: ChangeService (3.6.8d).

Reviewer: GO mit Auflagen 487-501, Variante D fuer
Approval (502-506).

Umgesetzt in fuenf Commits:
- f2fc220 (1/5) chat: ChatServiceError -> ServiceError,
  ChatOperationError(OperationError) fuer Konstruktor-None.
  LLMError/LLMTimeout/LLMUnavailable bleiben roh (502).
- c3450c5 (2/5) approval: Repo-Fehler propagieren.
  decide: ApprovalNotFoundError -> 404,
  ApprovalStateError -> 409, ApprovalServiceError -> 400.
  Basisklasse ApprovalRepositoryError -> 500.
- c7f2649 (3/5) inventory: InventoryOperationError neu.
  InventoryServiceError (Format) -> 404 (Pfad-Parameter).
- b0834d0 (4/5) audit_reader: AuditReaderOperationError neu.
- (5/5) Doku-Nachzug: DESIGN_DECISIONS §11,
  SECURITY_REVIEW_LOG, PHASES, CONTEXT_PROMPT.

Tests: 805 passed (Vollsuite, venv).

## Phase 3.6.15d — Chat-Klassifikations-Bug  [x]

Ziel: Der 3B-Chat darf Zustandsfragen nicht mehr als
Konzeptfragen klassifizieren und muss bei kritischen
Assessments auf 7B umschalten.

Bug (in Reviewer-Runde belegt):
- B1: _classify_question -- concept matched "was ist"
  auch bei Zustandsfragen.
- B2: _STATE_QUESTION_RE zu eng, kein Auto-Switch
  bei "Sind kritische Alarme da?".

Reviewer: GO mit Auflagen 507-522.
Commit f7b0fba.

Ergebnis (Live, A512):
- "Was ist heute Nacht passiert?" -> 7B auto_critical_state.
- "Sind kritische Alarme da?"     -> 7B auto_critical_state.
- "Was ist ein Portscan?"         -> 3B concept
  (unveraendert, korrekt).

Tests: 827 passed (Vollsuite, venv).
Neu: tests/unit/test_chat_classify.py (22 Tests).

Offen: Punkt 22 (Sanity-Check-Neumessung) im
SECURITY_REVIEW_LOG.

## Zwischenblock Punkt 22 — Sanity-Check-Neumessung  [x]

Ziel: pruefen, ob der Sanity-Check nach 3.6.15d
feuert (vorher 0 von 14 kritischen Faellen).

Vorgehen: 25 Fragen live gegen chat_cli.py
(8 kritisch-interpretation, 2 kritisch-fact,
5 fact, 5 concept, 2 detail, 1 fact-list,
2 sonstige). Auswertung aus audit-logs.

Ergebnis:
- chat_answer_contradicts_context: 2 (vorher 0).
- llm_retry: 0 (korrekt: beide bereits 7B).
- Auto-Switch: 10 von 15 LLM-Faellen auf 7B.
- Concept: 5 von 5 auf 3B (Auflage 517 bestaetigt).
- Fact: 9 Fragen deterministisch, kein LLM.

Sanity-Check funktioniert. Kein Fix noetig.
Punkt 23 neu (Audit model_reason=null bei fact/detail).
Keine Code-Aenderung in diesem Block.

## Phase 3.6.16 — Globale Suche  [x]

Ziel: zentrale Suche in der Topbar, die alle
Informationen zu einem Schlagwort zusammenzieht.

Kategorie 3 (RBAC pro Quelle, Input-Validierung,
Output-Escaping). Reviewer: Auflagen 365-379
+ 523-552. Commit c3b962b.

Umgesetzt:
- Migration 0008: search.run (admin + operator).
- core/search/repository.py (SearchRepository).
- core/services/search_service.py.
- apps/dashboard/routes_search.py (GET /search).
- apps/dashboard/templates/search.html.
- Topbar: Suchfeld mittig, topbar-title entfaellt.
- Kein Logout-Dropdown in 3.6.16 (A535/A536,
  eigener Zwischenblock).

Limits (A531): 20 pro Quelle. Kein globales Limit.
Kein "Erste 20 von N"-Hinweis (A371).

## Zwischenblock 3.6.16-topbar-usermenu  [x]

Ziel: User-Bereich in der Topbar mit Dropdown und
Logout. Der Logout-Button war seit 3.6.7b offen.
A535/A536: eigener Zwischenblock nach 3.6.16.

Reviewer: GO mit Auflagen 561-570. Commit 45853f3.

Umgesetzt:
- topbar.html: <details>/<summary>, person.svg,
  Name, Logout-Formular POST /logout mit CSRF.
- person.svg (lokal, currentColor, stroke-width 2).
- components.css: .user-menu*-Klassen,
  @media (max-width:400px) blendet Name aus.
- Kein JS (A562), nav.js unveraendert (A569).
- Tests: 6 neu in test_dashboard_nav.py.

Tests: 861 passed (Vollsuite, venv).

## Zwischenblock Punkt 23 — Audit model_reason  [x]

Aus der Punkt-22-Messung: chat_answered-Audit-
Eintraege in den Pfaden fact, detail_append,
no_context trugen model_reason=null.

Kategorie 2. Commit dccebf1.

Fix:
- apps/security_ai/chat.py: _log("chat_answered", ...)
  uebergibt model_reason in den drei Pfaden.
- Tests: 3 neu in tests/unit/test_chat.py.

Tests: 864 passed (Vollsuite, venv).

## Zwischenblock Punkt 16 — gunicorn + ProxyFix  [x]

Ziel: Flask dev-Server durch gunicorn ersetzen;
Login-Rate-Limit pro Client statt global.

Auflagen 642-659 (Kategorie 3).

Erledigt (16a, Commit <hash>):
- pyproject extra "prod": gunicorn>=21.0.
- apps/dashboard/wsgi.py.
- app.py: ProxyFix (x_for=1, x_proto=1, x_host=1).
- deploy/gunicorn.conf.py (2 Worker, 2 Threads,
  timeout 180, journal).
- systemd-Unit ExecStart auf gunicorn.
- Tests: ProxyFix aktiv, wsgi-Quelltext.

Erledigt (16b, Commit b4a21e4, nach Betriebsakt):
- gunicorn --check-config: OK (als security-ai).
- systemd-Start: active, Main + 2 Worker.
- ss -ltnp: 127.0.0.1:5000.
- HTTPS /login -> 200, POST mit falschem
  CSRF -> 400.
- control_socket_disable = True.

## Zwischenblock Punkt 9 — Rate-Limit Multi-Worker  [x]

Ziel: Rate-Limit fuer /api/chat Multi-Worker-fest.
Ausloeser: gunicorn mit 2 Workern (Punkt 16a) ->
In-Memory-Limit verdoppelte sich faktisch.

Kategorie 3, Auflagen 663-676, Option B.
Commit c4a1fa0.

Umgesetzt:
- Migration 0009: chat_rate_hits + Index.
- RateLimitService(conn): DELETE + COUNT + INSERT,
  BEGIN IMMEDIATE, Fail closed bei sqlite3.Error.
- routes_chat.py: pro Request, g.conn, Werte aus
  app.config.
- Login-Rate-Limit unveraendert.
- Tests: 7 neu in test_rate_limit_service.py,
  4 in test_dashboard_chat.py umgestellt.

Tests: 879 passed (Vollsuite, venv).

## Phase 3.6.18a — category durchsuchbar  [x]

Bugfix aus 3.6.16: risk_assessments.category in die
Suchfelder aufgenommen (A530).

## Phase 3.6.18b — Fact-Antwort-Stil  [x]

Labels statt Rohkategorien, dynamischer Zeitraum,
"Vorkommen" statt "Assessments". Commit 7a92b54.
Punkt 31, Auflagen 821-854.

## Phase 3.6.18c — nav_links im Fact-Pfad  [x]

Auffaelligkeits-Antwort liefert Navigations-Link
auf /alerts. ChatResponse.nav_links, API 8 Schluessel,
chat.js renderNavLinks. Commit 7b234df.
Punkt 33, Auflagen 858-881.

## Zwischenblock Punkt 28 — Chat-Kontext  [x]

Dashboard-Chat bekommt Kontext
(core/context/builder.build_chat_context).
CLI und Dashboard nutzen denselben Builder.
Commit a2b58c1, Auflagen 719-728.

## Zwischenblock Punkt 29 — Wert-Synonyme  [x]

core/search/synonyms.yaml + synonyms.py.
Suchbegriffe werden auf Synonym-Zielwerte erweitert.
Commit 0ede98f, Auflagen 776-790.

## Zwischenblock Punkt 30 — Links im Chat  [x]

fact/detail_append-Antworten liefern strukturierte
Link-Liste (core/context/links.py). API-Antwort
7 Schluessel. Commit f737d3f, Auflagen 757-772.

## Punkt 11 — SSH Key-only  [x]

Betriebsakt, kein Code. sshd_config:
PermitRootLogin prohibit-password,
PasswordAuthentication no, PubkeyAuthentication yes.
Key windows@... in authorized_keys. Commit d1602ef.

## Punkt 32 — Klassifikations-Luecke "gibt es"  [x]

_FACT_RE um "gibt es" erweitert, Veto gegen
Bewertungsworte. Commit 213ab7b, Auflagen 804-811.

## Zwischenblock Lint/Typen  [x]

ruff 452 -> 122, mypy 89 -> 71 (echte Typfehler
15 -> 0). Auto-Fix-Kategorien I001, UP017,
kleine Gruppen, F401. Gruppe 2+3 (5 Fixes).
Punkt 41 (B010-Regression) gefunden und behoben.
Commits 540b205, 3a5dbab, 6426967, d6ecc01,
3b20891, 6ec5c12, 9697c22, c1d2fe2, c05283e,
2bdc16b, 75b5ec1, b3db49c, 01466e0.

## Doku-Nachzug README + PHASES  [x]

README repariert (Heredoc-Vorfall 5b5a727),
- Vorfall-Nachtrag 2026-09-28: PROJECT_VISION.md
  Heredoc-Kopfzeile entfernt (A883-Klasse, zweiter
  Fall, Datei vollstaendig). Details in
  docs/SECURITY_REVIEW_LOG.md.
Kernzahlen 950 Tests. PHASES 3.6.10/3.6.11
abgehakt. Commits e0a6aa4, 4cc0a45, 8e79495.

## Phase 5 — Admin AI  [ ]

Optional, Cloud-basiert, ueber MCP. Setzt lokale KI
(Phase 3.5) voraus. Foederation ueber core/protocol/.

Voraussetzungen: Phase 3.5 (lokale KI).
Siehe PROJECT_VISION.md, Abschnitt 2.1 (Security
Master AI).

## Phase 6 — DSGVO-Konformitaet  [ ]

Ziel: Das System wird in einer Firma betreibbar,
ohne gegen DSGVO zu verstossen.

Voraussetzungen: Core fertig (Stufen 1-2.5 heute).
Siehe PROJECT_VISION.md, Abschnitt 7 (Grundprinzipien,
Punkt 11) und Abschnitt 8 (Stufe 4, Enterprise,
DSGVO-Konformitaet).

Skizze:
- Loeschkonzept fuer audit-logs (systemd-Timer oder
  Cronjob, Frist konfigurierbar).
- Pseudonymisierung nach Frist (IP-Hashing oder
  Kuerzung).
- Betroffenenrechte-Query ("zeige alle Eintraege
  fuer actor X").
- Verzeichnis von Verarbeitungstaetigkeiten
  (Doku-Template).
- TOM-Uebersicht (technische und organisatorische
  Massnahmen).
- AVV-Vorlage (falls SaaS-Modell).

## Phase 7 — Data Connectors  [ ]

Ziel: Anbindung an Firmensysteme (HR, Buchhaltung,
CRM, Tickets, M365) als Adapter unter der Security AI.

Voraussetzungen: Phase 6 (DSGVO-Basis).
Siehe PROJECT_VISION.md, Abschnitt 3 (Die Bridges)
und Abschnitt 8 (Stufe 4, Enterprise-Bridges).

Skizze:
- Connector-Interface (Adapter-Muster): API-Kenntnis,
  Schema-Mapping, Sandbox-Ausfuehrung, Audit-Pflicht.
- Erster Connector (Auswahl spaeter): HR (Personio,
  SAP HR, Workday), Buchhaltung (DATEV, SAP FI),
  CRM (Hubspot, Salesforce), Tickets (Jira, Zendesk),
  M365 (Microsoft Graph).
- Schema-Mapping (Firmen-Datenmodell auf
  Principal/Role/Permission).
- Loeschkonzept greift auf Connector-Daten
  (Phase-6-Mechanik wird genutzt).
- Bridges sind codeseitig vorbereitbar (PROJECT_VISION,
  Abschnitt 3, Vorbereitbarkeit): Public-API-Doku +
  Sandbox-Account reicht fuer die erste Version.

## Phase 8 — LLM-Bridges  [ ]

Ziel: Cloud-KI-Anbindung (Anthropic, OpenAI,
Azure OpenAI, DeepSeek) ueber offizielle Protokolle
(MCP).

Voraussetzungen: Phase 6 (DSGVO-Basis), AVV mit
den Anbietern. Phase 7 (Daten zuerst, dann
Intelligenz).
Siehe PROJECT_VISION.md, Abschnitt 10 (MCP-Kopplung)
und Abschnitt 8 (Stufe 4, Enterprise-Bridges).

Skizze:
- MCP-Client fuer die Security AI und die Security
  Master AI.
- AVV-Vorlage.
- Datenfluss-Kontrolle (was darf raus, was nicht).
- Opt-in pro Installation. Kein Cloud-Zwang.

## Phase 9 — Kunden-Mitarbeiter-KI  [ ]

Ziel: Die KI fuer die Mitarbeiter des Kunden.
Schnittstelle zwischen Mensch und Daten, mit
strikter RBAC-Kontrolle ueber die Security AI.

Voraussetzungen: Phase 8 (LLM-Bridges), Phase 7
(Data Connectors, erste Quelle).
Siehe PROJECT_VISION.md, Abschnitt 2.3
(Kunden-Mitarbeiter-KI) und Abschnitt 4 (Beispiele).

Skizze:
- Natuerlichsprachige Schnittstelle (Web-Chat).
- Jede Anfrage laeuft durch die Security AI
  (RBAC-Pruefung, Daten-Level).
- Schreibaktionen als Change Request mit Human
  Approval.
- Sonderfall "self" (eigene Daten).
- Kein direkter Datenzugriff, keine Umgehung der
  Security AI.

## Phase 10 — Physische Sicherheit  [ ]

Ziel: Zutritt, Tueren, Sensoren als eigene Schicht.
Personen als Entitaeten mit Raum-Level, Tool-Level,
Daten-Level.

Voraussetzungen: Core (Inventory, RBAC, Detection,
Events) steht.
Siehe PROJECT_VISION.md, Abschnitt 9 (Physische
Sicherheit) und Abschnitt 8 (Stufe 5).

Skizze:
- Raum-Sicherheitslevel (0-5).
- Zutrittstechnologien: RFID, Magnetkarte, PIN,
  optional Biometrie (Plugin-System).
- Personen als Entitaeten (ID, Name, Level,
  Zeiteinschraenkungen, Historie).
- Einheitliches Event-Schema (digital + physisch).
- Ethische Leitplanken (PROJECT_VISION, Abschnitt 9.5)
  sind verbindlich: keine Gesichtserkennung ohne
  Freigabe, keine Bewegungsprofile.

## Phase 11 — Ganzheitliche Korrelation  [ ]

Ziel: Digitale und physische Sicherheit korrelieren.
Zusammenhaenge erkennen, die einzelne Systeme nicht
sehen.

Voraussetzungen: Phase 10 (physische Sicherheit),
Phase 3.5 (lokale KI fuer Erklaerungen), ggf.
Phase 5 (Admin AI fuer Korrelation ueber Standorte).
Siehe PROJECT_VISION.md, Abschnitt 9.4
(Korrelationsregeln) und Abschnitt 8 (Stufe 6).

Skizze:
- Korrelationsregeln: access_level_mismatch,
  access_outside_hours, digital_without_physical,
  physical_without_digital, access_after_departure,
  unusual_pattern, tailgating.
- Deterministische Regel-Engine (kein LLM).
- LLM erklaert nur.
- Alarmierung ueber bestehende Kanaele (Telegram,
  Dashboard).


## Empfehlungen aus Doku-Audit 2026-09-23

### Fuer 3.6.10 / 3.6.11 (Optik)

- 3.6.10 zuerst (Kategorie 1, CSS-only):
  .table auf <700px, .topbar, .card, .form-input.
  Keine Template-Aenderung.
- 3.6.11 danach (Kategorie 3): Hamburger-Navigation.
  Button in topbar.html, Toggle in static/js/nav.js,
  extern, addEventListener, kein onclick=, kein
  Inline-<script>, keine style="...".
- Bei neuen Templates: CSP-Konformitaet pruefen.
  Kein |safe, kein style, kein on*, kein inline JS.
- Bei neuen Routes: Kategorie 2 (wichtig) mindestens.

### Fuer 3.7 (Feinschliff)

- Charts: Chart.js lokal einbinden (kein CDN).
  CSP script-src 'self' verbietet CDN.
- Live-Timeline: SSE oder Polling. Bei SSE:
  eigener Endpoint, CSP connect-src 'self' deckt ab.
- Suche: Backend-Endpoint + Frontend. Kein Client-
  Side-Filter ueber alle Daten.

### Fuer 3.8 (Security-Audit)

- Werkzeuge: Bandit, Safety, pip-audit, Ruff -S.
- Grep-Checks: eval, exec, shell=True, SQL-Concat.
- Review-Chat: pro Ordner systematisch
  (core/, harness/, apps/, tools/, scripts/).
- Ergebnis in docs/SECURITY_AUDIT.md.

### Offene Punkte vor 3.8

Siehe docs/SECURITY_REVIEW_LOG.md, Punkte 1-11.
Insbesondere:
- Punkt 5: ChatServiceError -> OperationError.
- Punkt 6: Fehlerklassen-Trennung in Alt-Services.
- Punkt 7/8: DESIGN_DECISIONS § 2/§ 11 (in diesem
  Doku-Audit nachgetragen).
- Punkt 10/11: HTTPS und SSH-Zugang.


## Empfehlungen aus Doku-Audit 2026-09-23

### Fuer 3.6.10 / 3.6.11 (Optik)

- 3.6.10 zuerst (Kategorie 1, CSS-only):
  .table auf <700px, .topbar, .card, .form-input.
  Keine Template-Aenderung.
- 3.6.11 danach (Kategorie 3): Hamburger-Navigation.
  Button in topbar.html, Toggle in static/js/nav.js,
  extern, addEventListener, kein onclick=, kein
  Inline-<script>, keine style="...".
- Bei neuen Templates: CSP-Konformitaet pruefen.
  Kein |safe, kein style, kein on*, kein inline JS.
- Bei neuen Routes: Kategorie 2 (wichtig) mindestens.

### Fuer 3.7 (Feinschliff)

- Charts: Chart.js lokal einbinden (kein CDN).
  CSP script-src 'self' verbietet CDN.
- Live-Timeline: SSE oder Polling. Bei SSE:
  eigener Endpoint, CSP connect-src 'self' deckt ab.
- Suche: Backend-Endpoint + Frontend. Kein Client-
  Side-Filter ueber alle Daten.

### Fuer 3.8 (Security-Audit)

- Werkzeuge: Bandit, Safety, pip-audit, Ruff -S.
- Grep-Checks: eval, exec, shell=True, SQL-Concat.
- Review-Chat: pro Ordner systematisch
  (core/, harness/, apps/, tools/, scripts/).
- Ergebnis in docs/SECURITY_AUDIT.md.

### Offene Punkte vor 3.8

Siehe docs/SECURITY_REVIEW_LOG.md, Punkte 1-11.
Insbesondere:
- Punkt 5: ChatServiceError -> OperationError.
- Punkt 6: Fehlerklassen-Trennung in Alt-Services.
- Punkt 7/8: DESIGN_DECISIONS § 2/§ 11 (in diesem
  Doku-Audit nachgetragen).
- Punkt 10/11: HTTPS und SSH-Zugang.
