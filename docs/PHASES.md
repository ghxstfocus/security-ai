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

## Phase 3.6.11 — Hamburger-Navigation  [ ]

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

## Phase 3.6.16 — Globale Suche  [ ]

Topbar-Umbau (Teil von 3.6.16, ersetzt den Titel):
- Suchfeld zentral zwischen Hamburger und User.
- Seitentitel (div.topbar-title) entfaellt — redundant
  zum Seiten-<h1>.
- User-Bereich:
  * Personen-SVG + Name + Dropdown-Pfeil.
  * Dropdown enthaelt NUR Logout (POST /logout).
  * Keine Profileinstellungen, kein Passwort-Link,
    kein Language-Switch (Enterprise-System,
    administrativ).
  * <=400px: Name verkuerzen oder ausblenden,
    nur Icon + Pfeil.

Ziel: zentrale Suche in der Topbar, die alle
Informationen zu einem Schlagwort zusammenzieht.
Beispiele: IP, Datum, User, Change-ID, Event-ID.

Kategorie 3 (RBAC pro Quelle, Input-Validierung,
Output-Escaping). Reviewer-Freigabe: Auflagen 365-379
(Reviewer-Chat, 2026-09-24).

Kurzfassung Auflagen:
- 365: Detail-Route je Quelle ist die bestehende
  Route (/changes/ID, /inventory/ID, /audit/ID, ...).
- 366: Chat ohne Detail-Route: direkte Antwort.
- 367: jeder Treffer ist <a href=...>.
- 368: Limit 20 pro Quelle in der Vorschau.
- 369-370: q escaped in URL und im Template.
- 371: Limit 50 pro Quelle in der Such-Ergebnisliste.
- 372: RBAC pro Quelle (Operator und Admin sehen alles
  in der DB; Viewer 403).
- 373: Route apps/dashboard/routes_search.py,
  Service core/services/search_service.py.
- 374: Input-Validierung (len 1..200, Zeichen-Whitelist,
  keine SQL-Wildcards, parametrisierte Queries).
- 375: keine Datei-Pfad-Suche.
- 376: Response-Whitelist (kein args_json, kein
  password_hash, kein session_id).
- 377: Test-Matrix (RBAC, Input, Limit, XSS, CSP).
- 378: Ergebnis-Darstellung via <details>/<summary>.
- 379: Topbar-Suchfeld erst mit 3.6.16.

MVP-Umfang:
- Nur Operator/Admin.
- Exakte Treffer, keine Wildcards, keine Grammatik.
- Nur SQLite-Quellen (principals, inventory.devices,
  whitelisted_devices, approvals, change_requests).
- Kein audit-logs-Volltext.
- Kein Datums-Parsing.
- Nur nach Enter (keine Live-Suche).
- Kein Audit der Suchanfragen.
- q in URL (/search?q=...).

Reihenfolge: nach 3.6.11, 3.6.13, 3.6.14.

## Phase 5 — Admin AI  [ ]

Optional, Cloud-basiert, ueber MCP. Setzt lokale KI
(Phase 3.5) voraus. Foederation ueber core/protocol/.


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
