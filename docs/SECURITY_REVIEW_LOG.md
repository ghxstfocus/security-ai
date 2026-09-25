# Security Review Log

Protokoll der wichtigsten Review-Entscheidungen
aus der externen Review-Session (Audit-Chat)
waehrend Phase 3.5 und 3.6.

## Zweck

- Nachvollziehbarkeit: WARUM ist der Code so?
- Handoff: neue Chats (Bau oder Review) finden
  den Stand.
- Persistenz: Entscheidungen liegen in der Doku,
  nicht im Gedaechtnis eines Chats.

## Struktur

Strukturiert nach Themen, nicht nach Nummern.
Nummern nur da, wo eindeutig.

## Verworfene Ansaetze

### conftest.py fuer Dashboard-Fixture

Verworfen: tests/unit/conftest.py global.
Stattdessen: tests/unit/_helpers.py.
Grund: conftest.py gilt fuer alle Unit-Tests.
Dashboard-Fixture (admin1, viewer1) wuerde
versehentlich von anderen Tests angezogen.
Loesung: build_dashboard_app-Helper, explizit
importiert.

### include ... with fuer Partial-Parameter

Verworfen: {% include "x.html" with a=1 %}.
Grund: keine gueltige Jinja2-Syntax.
Stattdessen: Makro.

### 403-Test fuer Route /

Verworfen: test_index_403_without_device_read.
Grund: alle realen Rollen (admin, operator,
viewer, system) haben device.read.
Der generische RBAC-Pfad ist in
test_access_denied_errorhandler_403 abgedeckt.

## Sicherheitsentscheidungen nach Thema

### Authentifizierung und Session

- Passwort-Hashing: pbkdf2_sha256, 600k
  Iterationen.
- verify_password mit hmac.compare_digest.
- Fail closed bei fehlendem password_hash.
- Session-Cookie: HttpOnly, Secure,
  SameSite=Strict, max_age=30 min.
- SESSION_COOKIE_NAME = "security_ai_session"
  (explizit, nicht "session").
- Session-ID-Rotation bei jedem Login.
- Idle-Timeout 30 min, VOR touch geprueft.
- SessionRepository intern UTC-aware.
- purge_expired loescht nur ALTE widerrufene
  Sessions (nicht frische).
- revoke_all_for_principal bei Passwort-Aenderung.
- Ab 3.6.12 (HTTPS hinter nginx) kein temporaeres
  Secure=False mehr noetig; SESSION_COOKIE_SECURE=True
  wird nicht mehr abgeschwaecht. Offener Punkt 10
  (HTTPS fuer Dashboard-Test) ist damit geschlossen.

### CSRF

- Synchronizer-Token in session["_csrf_token"].
- Token via secrets.token_urlsafe(32).
- Vergleich mit hmac.compare_digest.
- Token in jedem Form (Makro csrf_field).
- Token rotiert nach Login.
- POST /logout prueft CSRF.
- Ausnahme: nur mit Authorization-Header und
  SameSite=Strict.
- 3.6.8e: JSON-Endpoints nutzen Header
  X-CSRF-Token statt Form-Feld. Begruendung:
  Querschnittsregel (kein Body-Parsing vor
  CSRF-Check), keine Vermischung von Body-
  Whitelist und CSRF-Feld. validate() bleibt
  unveraendert (vergleicht Strings).
- _inject_csrf als zweiter context_processor
  liefert csrf_token in jedes Template.
  get_or_create rotiert nicht (idempotent);
  Test test_csrf_token_stable_across_requests.

### Rate-Limit

- LoginAttemptRepository pro IP.
- LOGIN_MAX_FAILURES = 5 (401 + kein weiterer
  Hint).
- LOGIN_HARD_LIMIT = 20 (429, DoS-Schutz).
- LOGIN_WINDOW_SECONDS = 900 (15 min).
- Kein time.sleep (600k pbkdf2 reicht).
- 3.6.8e: RateLimitService (core/services/)
  fuer /api/chat. Key = principal_name (nicht
  Session-ID, nicht IP). In-Memory dict,
  threading.Lock. WINDOW_SECONDS=60,
  MAX_REQUESTS=10. 429 + Retry-After.
  Kein Audit/Log bei Treffer (sonst fuellt
  ein Angreifer die Audit-Logs).
  Single-Process heute; bei Multi-Worker
  spaeter gemeinsamer Store (Redis/DB).

### User-Enumeration

- Dummy-Hash bei PrincipalNotFound.
- Dummy-Hash lazy berechnet (nicht import-time).
- verify_password gegen Dummy auch bei
  is_active=False.
- Response fuer alle Fehlerfaelle identisch
  (Text, Timing).
- Unknown Principal landet im Rate-Limit.

### Authorization (RBAC)

- AccessChecker: check, require_permission,
  role_of, permissions_of, from_conn.
- role_of -> str | None, permissions_of ->
  frozenset (leer bei unbekannt).
- require_permission bleibt im Checker.
- before_request Reihenfolge:
  1. g.conn, g.audit
  2. PUBLIC_PATHS -> return None
  3. Sicherheitsnetz (Route ohne Dekoration -> 403)
  4. Session-Check (redirect /login)
  5. Idle-Timeout
  6. touch
  7. g.principal, g.access_checker,
     g.access_service
  8. require_permission(g.principal,
                       view_fn._required_permission)
- whoami mit @require_permission("chat.ask").
- logout mit @require_permission("chat.ask")
  (nicht PUBLIC, nicht ROUTES_CSRF_ONLY).
- Platzhalter-Routen mit Permission:
  / -> device.read
  /inventory -> device.read
  /alerts -> device.read
  /approvals -> approval.view
  /changes -> change.view
  /chat -> chat.ask
  /users -> principal.manage
  /roles -> role.manage
  /audit -> audit.read
  /settings -> role.manage

### Open-Redirect-Schutz

- _safe_next: blockt "", nicht-/, //, /\,
  \r, \n, \x00.
- Zusaetzlich: URL-Decode einmal
  (urllib.parse.unquote), dann Validierung.
- Grund: %2F%2Fevil.com und /%5Cevil.com
  sind Bypaesse.

### XSS

- Jinja2 autoescape aktiv (Flask-Standard).
- Kein |safe ohne Doku + Test.
- html.escape NICHT in auth.py::login_form
  (Jinja escaped automatisch, sonst doppeltes
  Escaping).
- Chat-Antworten als Text (<pre>),
  nicht als HTML.
- Kein innerHTML mit Daten in JS.
- addEventListener statt onclick.

### CSP und Security-Header

- CSP-Header exakt:
  default-src 'self';
  script-src 'self';
  style-src 'self';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self';
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  object-src 'none';
- Kein 'unsafe-inline', kein 'unsafe-eval'.
- Konsequenz: keine style="..." in Templates,
  kein <style>-Block, kein on*=,
  kein inline <script>.
- Zusaetzliche Header:
  X-Content-Type-Options: nosniff,
  X-Frame-Options: DENY,
  Referrer-Policy: same-origin,
  Permissions-Policy (geolocation, camera,
  microphone, payment, usb, interest-cohort).
- after_request setzt Header (auch auf 500er).

### venv und Umgebung

- Immer /opt/security-ai/.venv/bin/python3.
- Tests immer aus /opt/security-ai (CWD).
- scripts/* sind Werkzeuge, keine Bibliothek.
- pyproject: PyYAML >= 6.0.
- pyproject: [tool.setuptools.packages.find]
  include [apps*, core*, harness*, tools*],
  exclude [data*, deploy*, changes*,
  policies*, detection*, tests*, docs*,
  scripts*, audit-logs*].

### Audit

- AuditWriter ist App-Singleton in
  app.extensions["audit_writer"].
- Audit-Kinds Login/Session:
  login_success, login_failed, login_locked,
  logout, session_timeout.
- Audit-Kinds RBAC: rbac_denied.
- Audit-Kinds AccessService:
  principal_created, principal_active_changed,
  principal_password_changed,
  permission_assigned, permission_revoked.
- Audit-Kinds Chat: chat_query, chat_answered,
  chat_access_denied, chat_llm_error,
  chat_model_callback_failed.
- Audit NIEMALS: Passwort, Hash, Session-ID,
  CSRF-Token.
- user_agent auf 200 Zeichen kuerzen.
- principal: None oder str (nicht "").

### Fail closed

- Fehlendes SECRET_KEY -> ConfigError.
- SECRET_KEY < 32 Byte -> ConfigError.
- Fehlender audit_writer -> ServiceError.
- Fehlender session_repo -> AccessServiceError.
- Unbekannte Rolle -> ApprovalRepositoryError.
- Fehlender HTTP-Status -> 500 generisch
  (kein Stacktrace).
- Class-Fehler -> Fallback auf sichere Defaults.

## Prozess-Regeln (Review)

- Vor jedem Patch einer bestehenden Datei:
  erst cat, dann Python-Patch mit
  assert count == 1.
- Kein sed auf Python-Code.
- Keine Umlaute in Code-Bloecken.
- Immer /opt/security-ai/.venv/bin/python3.
- Bei Kategorie 3 (Sicherheit): Code VOR
  Ausfuehrung an Reviewer.
- Bei Auflagen mit Jinja-Syntax oder API:
  vorher pruefen, nicht aus dem Gedaechtnis.
- Nach jedem Schritt: wc -l, py_compile,
  pytest -q, git commit.

## Handoff-Hinweise

- Neuer Chat liest: docs/CONTEXT_PROMPT.md,
  docs/DESIGN_DECISIONS.md, diese Datei,
  docs/PHASES.md.
- Ausgelagerte Inkonsistenzen:
  docs/INCONSISTENCIES_FOUND.md (heute leer;
  Struktur vorhanden fuer kuenftige Funde).
- Offene Punkte siehe Abschnitt `## Offene Punkte` unten.
- Aktuelle Sicherheits-Entscheidungen pro Thema
  in dieser Datei.
- Bei Syntax- oder API-Auflagen: pruefen,
  nicht aus dem Gedaechtnis.

## Chronologie

- 3.6.4: AuditReaderService.
- Venv-Umstellung.
- 3.6.5: Flask-App-Factory + RBAC-Middleware.
- 3.6.6: Login + Logout + CSRF + Rate-Limit +
  Audit.
- 3.6.7a: Static (CSS, JS, SVG).
- 3.6.7b: base.html + Partials + CSP.
- 3.6.7c: login.html als Template.
- 3.6.7d: index.html + Route /.
- 3.6.7e: CSP-Test + PHASES.
- 3.6.8a: /inventory (device.read, InventoryService).
  Fix: CSS-Klassen an reale components.css angeglichen.
- 3.6.8b: /alerts (alert.view, AuditReaderService).
  Fix: AuditReaderService.list_recent_assessments nutzt
  self._audit.base_dir (Audit-Quelle == App-Konfig).
  Review: NO-GO-Korrektur war der base_dir-Bug.
- 3.6.8c: /approvals (approval.view + approval.decide,
  CSRF, Variante A um ApprovalQueue).
  NO-GO-Korrekturen: unmatched-route-403-Test,
  session_transaction-Helper, decision_reason-Anzeige.
- 3.6.8d: /changes (change.view + change.create).
  Review: NO-GO -> zwei Fehlerklassen eingefuehrt
  (ServiceError Format, OperationError Betrieb).
- 3.6.8e: /chat + /api/chat (chat.ask, Rate-Limit,
  CSRF-Header, _inject_csrf).
  Review: NO-GO -> CSRF-Header statt Body, 502 bei
  LLM-Fehler, Rate-Limit jetzt, chat.js bedingt,
  Test-Kontext app_context -> test_request_context.
- 3.6.8f: /users (principal.manage, principal_to_view,
  MIN_PASSWORD_LEN=12, list_roles mit principal.manage).
  Review: NO-GO -> create_principal ohne password_hash,
  MIN_PASSWORD_LEN in der Service-Schicht, Test-Passwoerter
  auf 12 Zeichen, self-deactivate verboten.
- 3.6.8g: /roles (role.manage, role_to_view,
  permission_to_view, assign/revoke, self-critical
  Warnung bei Entzug aus eigener Rolle).
  Review: GO mit Auflagen 179-189, Nachtrag 190-194
  (praezise Warn-Bedingung, fester Wortlaut).
- 3.6.8h: /audit (audit.read, Tag-Filter, UTC heute
  default, Detail mit formatiertem details, kein
  read_all im UI).
  Review: GO mit Auflagen 195-206 (Query-Parameter
  400, Pfad-Parameter 404, kein Reflexions-Dump).
- 3.6.8i: /settings (role.manage, read-only Konfig-
  Anzeige, kein SECRET_KEY, kein os.environ-Dump,
  kein Existenz-Check).
  Review: GO Variante A mit Auflagen 207-221
  (Test-Umbenennung wegen tmp_path-Kollision).
- 3.6.8 Doku-Abschluss: 3beab99 (a-i alle [x]).
- 3.6.10: responsive Tabellen (CSS-only, E+B).
- 3.6.11: Hamburger-Navigation (Sidebar-Overlay,
  nav.js, CSP-konform).
- 3.6.12: HTTPS via nginx + eigene CA.
  Fix: Migrationen 0006/0007 auf Produktions-DB
  nachgezogen, Audit-Log-Rechte korrigiert.
- 3.6.13: Systemvoraussetzungen (DEPLOYMENT §3d).


## Offene Punkte (Stand 3.6.8)

1. AuditReaderError-Namenskollision:
   `core/reporting/audit_reader.py::AuditReaderError`
   hat denselben Namen wie der fruehere Service-
   Fehler. Service-Seite umbenannt zu
   `AuditReaderServiceError`. Modul-Seite in
   Phase 3.6.9+ umbenennen (Vorschlag:
   `AuditJsonlError`).

2. systemd `WorkingDirectory=/opt/security-ai`:
   `audit-logs/` und `detection/rules.yaml` werden
   relativ zum CWD gelesen. Deployment-Doku +
   Unit-File in Phase 3.6.9.

3. Rollen-Review: kein Principal ohne
   `device.read` anlegen (sonst 403 nach Login,
   weil `/` device.read erfordert).

4. `WEB_SECURITY_CHECKLIST.md` § E auf strenge
   CSP korrigiert (kein `'unsafe-inline'`) —
   Quelle jetzt `DESIGN_DECISIONS §16`.

5. ChatServiceError nicht in ServiceError-Hierarchie.
   Liegt in apps/security_ai/chat.py, erbt von
   RuntimeError. Route faengt nicht, globaler
   500. Eigener Aufraeum-Block: ChatServiceError
   -> OperationError (Auflage 87, 3.6.8e).

6. ApprovalService/InventoryService/
   AuditReaderService mischen Format- und
   Betriebsfehler in einer Klasse. Sollten auf
   ServiceError/OperationError-Trennung umgestellt
   werden (Vorbild: ChangeService, 3.6.8d).
   Eigener Aufraeum-Block.

7. DESIGN_DECISIONS § 2 (tool-Tabelle):
   ChangeService -> change_service ergaenzen
   (Auflage 52, 3.6.8d).

8. DESIGN_DECISIONS § 11: Regel
   "Format-Fehler -> ServiceError-Subklasse -> 4xx.
   Betriebs-Fehler -> OperationError-Subklasse -> 5xx."
   ergaenzen (Auflage 74, 3.6.8d).

9. Rate-Limit Multi-Worker: RateLimitService
   ist In-Memory (Single-Process). Bei mehreren
   Workern gemeinsamer Store (Redis/DB)
   (Auflage 98, 3.6.8e).

10. HTTPS fuer Dashboard-Test im Browser:
    SESSION_COOKIE_SECURE=True (apps/dashboard/app.py:56)
    verhindert Login ueber HTTP. Browser schickt die
    Session-Cookie nicht zurueck, CSRF-Check schlaegt
    fehl -> 400 "Ungueltige Anfrage".
    Saubere Loesung: TLS (Self-signed oder Reverse-Proxy)
    vor Flask. Alternativ fuer lokalen Test:
    SSH-Tunnel + temporaer Secure=False, aber nur
    mit Bind 127.0.0.1 und sofortigem Rueckbau.
    Eigener Kategorie-3-Block (TLS/Auth).
    Siehe docs/PHASES.md offener Punkt "3.6.12 HTTPS".

11. SSH-Zugang Windows -> CT102:
    permitrootlogin without-password in der effektiven
    sshd-Konfig (sshd -T). root darf per Passwort nicht
    rein, Public-Key-Auth-Versuch ist fehlgeschlagen.
    Kein Blocker fuer 3.6.8f-i (Dashboard-Arbeit laeuft
    ueber die bestehende SSH-Session).
    Eigener Kategorie-3-Block (SSH-Zugang).

12. Test-Client / Orchestrator nie als root gegen die
    Produktions-DB. Immer via `runuser -u security-ai`.
    Anlass: ein root-Prozess hat am 2026-09-24 um 00:17
    per orchestrator-snapshot die Datei
    audit-logs/2026-09-24.jsonl als 644 root:root
    angelegt. Nachfolgende Login-POSTs des Service-Users
    security-ai scheiterten mit PermissionError, der
    globale 500-Handler lieferte Interner Fehler statt
    Redirect auf /login.

13. AuditWriter setzt beim Anlegen einer neuen Datei
    keinen expliziten Modus oder Owner. Bei versehentlichem
    root-Lauf entsteht 644 root:root statt 640
    security-ai:security-ai. Praevention: der AuditWriter
    setzt beim Datei-Erstellen explizit os.umask oder
    einen os.chmod auf 640 und prueft den Owner.
    Kategorie 3, eigener Block.

14. Service-Start prueft audit-logs/ nicht auf Konsistenz
    (Owner, Modus, Fremddateien). Ein inkonsistenter
    Zustand wurde erst durch einen 500er sichtbar, nicht
    beim Start. Praevention: beim App-Start audit-logs/
    pruefen und bei Inkonsistenz fail closed oder warnen.
    Kategorie 2/3, eigener Block.

15. Migrations-Tracking defekt ab 0003. Die Migrationen
    0003-0007 tragen sich nicht in schema_migrations ein;
    die DB steht deshalb auf Version 2, obwohl Tabellen
    0003-0005 existieren. Anlass: der Login-500er am
    2026-09-23/24 (fehlende Tabellen sessions und
    login_attempts aus 0006). Fix in dieser Session:
    init_db.py --no-principal erneut ausgefuehrt.
    Praevention: (a) Migrations-Tracking reparieren,
    (b) Deployment-Schritt fuer Migrationen in
    docs/DEPLOYMENT.md aufnehmen, (c) Service-Start
    prueft DB-Schema-Version. Kategorie 2/3, eigener Block.
    Erledigt in 3.6.15a: (a) ce25660 (Fix A+B),
    (c) 1cedb26 (Fix D), (b) Fix-C-Commit mit
    DEPLOYMENT 3e + deploy/systemd/-Vorlage.
    Der Punkt bleibt hier als Referenz stehen.

16. Flask dev-Server-Warnung.
    Der Service laeuft heute als Flask-dev-Server hinter
    nginx. Die Warnung "This is a development server"
    im journal wird im Heimnetz akzeptiert. Fix:
    gunicorn/uwsgi in eigener Runde. Kategorie 3.

17. check_schema_version auch beim security_ai-Start.
    Fix D (1cedb26) prueft die DB-Schema-Version nur
    beim Dashboard-Start (create_app). Der security_ai-
    Start hat heute keinen eigenen systemd-Pfad (nur
    manueller Aufruf). Wenn dieser Start gebaut wird,
    check_schema_version dort ebenfalls aufrufen.
    Kategorie 3, eigener Block (Reviewer-Auflage 398).

18. DEPLOYMENT 1 Topologie-Drift.
    docs/DEPLOYMENT.md Abschnitt 1 zeigt LXC 101
    (192.168.178.116, ruht), LXC 103 (.118, geplant),
    LXC 104 (.119, geplant). Aktuelle Umgebung ist
    CT102 (192.168.178.117, security-ai).
    Doku-Drift. Eigener Doku-Block nach 3.6.15.
    Kategorie 1 (Doku), Reviewer-Auflage 413.

19. Pro-Tabelle-Klassen fuer gezieltes Spalten-
    Ausblenden bei <500px. Heute global
    nth-child(n+4) in components.css (3.6.10).
    Kuenftig pro Tabelle eine Klasse (table-alerts,
    table-inventory, ...), damit pro Seite definiert
    wird, welche Spalten auf schmalen Displays
    wichtig sind. Ersetzt die globale Regel.
    Betrifft sechs Tabellen (inventory, audit,
    users, changes, approvals, alerts).
    Eigener Folgeschritt nach 3.6.14.
    Kategorie 2, Reviewer-Auflage 419.
