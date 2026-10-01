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

Nummern 633-637 wurden in einem Handoff
referenziert, aber nie belegt. Verworfen.
Nummerierung laeuft ab 633 neu (Runde
2026-09-27, Punkt 17 / 16).
Nummerierung: 958-965 waren Rahmenvorgaben
fuer den Wechsel in den neuen Chat.
Ab 966 wieder Auflagen fuer konkrete Bloecke.

## Diagnose 2026-09-27

Gesundheits-Check vor der naechsten Runde
(Auflagen 686-699). Kein Fix, nur Bestandsaufnahme.

Erledigt (alle bestanden):
- pytest --collect-only: 879.
- pip check: No broken requirements found.
- py_compile (alle .py): OK.
- git fsck --full: keine Fehler, keine dangling objects.
- sqlite3 PRAGMA integrity_check: ok.
- systemctl status: active (running), gunicorn
  Main + 2 Worker.
- journalctl -p err (24h): keine Eintraege.
- ss -ltnp: 5000 (127.0.0.1 gunicorn), 80+443
  (nginx), 22 (sshd). Erwartet, nichts Fremdes.
- nginx -t: OK.
- curl HTTPS /login (127.0.0.1 + security-ai.local):
  200.
- curl direkt Flask 127.0.0.1:5000/login: 200.
- gunicorn --check-config: OK (nach Betriebsakt).

Finding:
- pyproject.toml deklarierte dev-Dependencies
  (pytest, pytest-cov, ruff, mypy), aber im venv
  war nur pytest installiert. Behoben mit
  `pip install -e .[dev]`. Jetzt: ruff 0.16.9,
  mypy 2.3.1, pytest-cov 7.1.0.

Bestandsaufnahme (nicht behoben, eigene Runde):
- ruff check .: 435 Fehler, davon 334 automatisch
  fixbar. Top-Kategorien:
    I001 unsorted-imports: 102
    UP017 datetime-timezone-utc: 94
    F401 unused-import: 40
    RUF022 unsorted-dunder-all: 33
    UP037 quoted-annotation: 22
    C408 unnecessary-collection-call: 22
    BLE001 blind-except: 18
    Rest kleinere Kategorien.
- mypy apps core harness tools scripts:
  87 Fehler in 29 von 111 Dateien. Ueberwiegend
  fehlende Typannotationen (no-untyped-def),
  Beispiel: apps/dashboard/app.py.

Kein Fix in dieser Runde. Wenn der Nutzer will:
eigene Runde "Lint/Typen-Aufraeumen" (Kategorie 1/2).

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

Sortiert nach Commit-Zeit (aelteste zuerst, HEAD zuletzt).
Letzte Aktualisierung: 2026-10-01 (HEAD 5faa9aa).

- 3.6.4: AuditReaderService.
- Venv-Umstellung.
- 3.6.5: Flask-App-Factory + RBAC-Middleware.
- 3.6.6: Login + Logout + CSRF + Rate-Limit + Audit.
- 3.6.7a: Static (CSS, JS, SVG).
- 3.6.7b: base.html + Partials + CSP.
- 3.6.7c: login.html als Template.
- 3.6.7d: index.html + Route /.
- 3.6.7e: CSP-Test + PHASES.
- 3.6.8a: /inventory (device.read, InventoryService).
  Fix: CSS-Klassen an reale components.css angeglichen.
- 3.6.8b: /alerts (alert.view, AuditReaderService).
  Fix: list_recent_assessments nutzt self._audit.base_dir.
- 3.6.8c: /approvals (approval.view + approval.decide,
  CSRF, Variante A um ApprovalQueue).
- 3.6.8d: /changes (change.view + change.create).
  Review: NO-GO -> zwei Fehlerklassen (ServiceError,
  OperationError).
- 3.6.8e: /chat + /api/chat (chat.ask, Rate-Limit,
  CSRF-Header, _inject_csrf).
- 3.6.8f: /users (principal.manage, principal_to_view,
  MIN_PASSWORD_LEN=12, list_roles mit principal.manage).
- 3.6.8g: /roles (role.manage, role_to_view,
  permission_to_view, assign/revoke, self-critical
  Warnung bei Entzug aus eigener Rolle).
- 3.6.8h: /audit (audit.read, Tag-Filter, UTC heute
  default, Detail mit formatiertem details, kein
  read_all im UI).
- 3.6.8i: /settings (role.manage, read-only Konfig-
  Anzeige, kein SECRET_KEY, kein os.environ-Dump).
- 3.6.8 Doku-Abschluss: 3beab99 (a-i alle [x]).
- 3.6.10: responsive Tabellen (CSS-only, E+B).
- 3.6.11: Hamburger-Navigation (Sidebar-Overlay,
  nav.js, CSP-konform).
- 3.6.12: HTTPS via nginx + eigene CA.
  Fix: Migrationen 0006/0007 auf Produktions-DB
  nachgezogen, Audit-Log-Rechte korrigiert.
- 3.6.13: Systemvoraussetzungen (DEPLOYMENT §3d).
- 3.6.14: UI-Politur Alerts-Tabelle (bba4ac7).
  Badge-Label statt Rohkategorie (A424),
  format_ts/format_score_label/format_score in
  apps/dashboard/filters.py, .badge nowrap.
  alert_row.html entfernt (verwaist).
  Pro-Tabelle-Klassen als Punkt 19 verschoben.
- 3.6.15a: Migrations-Tracking (ce25660),
  Schema-Check im Dashboard (1cedb26),
  ExecStartPre + DEPLOYMENT 3e (dd10214).
- 3.6.15b: Audit-Rechte fail closed (a3589db).
  Fix 13 Option B, Fix 14 (check_audit_logs beim
  App-Start), Fix A (Test-Isolation in
  OrchestratorTests.setUp), Fix C (test_setup_isolation).
  Punkte 13/14 erledigt. Punkt 21 neu.
- 3.6.15c: Fehlerklassen-Trennung (Punkte 5/6).
  Variante D (Auflagen 502-506): Repo-Fehler
  propagieren, Route behandelt direkt.
  Fuenf Commits:
    f2fc220 chat: ChatServiceError(ServiceError)
            + ChatOperationError(OperationError).
    c3450c5 approval: Repo-Fehler propagieren,
            decide 404/409/400.
    c7f2649 inventory: InventoryOperationError.
    b0834d0 audit_reader: AuditReaderOperationError.
    34e44c7 Doku-Nachzug.
  Punkte 5 und 6 erledigt.
- 3.6.15d: Chat-Klassifikations-Bug behoben (f7b0fba).
  B1: _classify_question -- concept nur, wenn nicht
  _is_state_question. B2: _STATE_QUESTION_RE erweitert.
  Auto-Switch bei jeder Interpretation mit kritischen
  Assessments. Live verifiziert: 3B concept -> 7B.
- Punkt-22-Neumessung 2026-09-26 (25 Fragen, LLM live,
  Commit cca22ef):
  Sanity-Check feuert jetzt (2 Faelle), Auto-Switch
  greift (10/15 LLM auf 7B), Concept bleibt 3B (5/5),
  Fact-Pfad deterministisch (9). Retry 0, weil die
  2 Contradictions bereits 7B waren. Punkt 22 erledigt.
- 3.6.16: Globale Suche (c3b962b, 6dd50fa).
  Migration 0008 (search.run, admin+operator).
  core/search/repository.py, core/services/
  search_service.py, GET /search, search.html.
  Topbar-Suchfeld (topbar-title entfaellt).
  Limite 20 pro Quelle (A531). Punkte 365-379 + 523-560.
- 3.6.16-topbar-usermenu (45853f3, 554d9ef):
  <details>-Dropdown mit Logout. person.svg lokal,
  kein JS. CSRF-Feld im Logout-Formular.
  A535/A536: eigener Zwischenblock. Der seit 3.6.7b
  offene Logout-Button ist damit erledigt.
- Punkt 23 (dccebf1, 71a1095): chat_answered-Audit
  traegt model_reason auch in fact/detail_append/
  no_context. Drei neue Tests.
- Commit A (08b94de): offene Punkte 2, 7, 18.
  DEPLOYMENT §3e WorkingDirectory, Schema-Version
  7->8, Topologie-Drift behoben.
- Commit B (534a172): PROJECT_VISION aktualisiert,
  Phasen 6-11 angelegt (DSGVO, Data Connectors,
  LLM-Bridges, Kunden-Mitarbeiter-KI, Physische
  Sicherheit, Ganzheitliche Korrelation).
- WORKFLOW HR10 (d671aa8): Reviewer-Update nach
  jedem Block, verbindlich.
- Punkt 1 (b4c515c): AuditReaderError -> AuditJsonlError.
- PROJECT_VISION neu (3328ef8, 5b3de3b GitHub).
  Drei KI-Ebenen, Bridges, DSGVO, physische
  Sicherheit. Bridge-Vorbereitbarkeit (90da86b).
  Phasen 6-11 (706ab5e).
- Punkt 3 (e45bc87): create_principal erzwingt
  device.read. Doku in PERMISSIONS.md und
  DESIGN_DECISIONS §10. Fail closed beim Anlegen
  statt beim Login. Log-Markierung: 3b36753.
- 3.6.17 (d4c6fa7): SearchRepository setzt
  row_factory defensiv.
- Punkt 19 (0b970ec, c05d4fe): Pro-Tabelle-Klassen
  <500px. Sieben Tabellen-Klassen, globale
  nth-child-Regel ersetzt. Auflagen 614-622.
- Punkt 21 (1f28feb): Gemischte audit-logs.
  21.-25.09. enthalten Burst-Eintraege aus
  OrchestratorTests (210/176/38/14/30 Burst-Sekunden).
  Fix in 3.6.15b. Dokumentiert in
  audit-logs/README.md. Kein Eingriff in die Logs.
- Punkt 17 (6f37fa5): check_schema_version beim
  security_ai-Start geklaert (kein Startpfad heute).
  Punkt 26 neu.
- Nummerierungs-Vermerk (87aa614): 633-637 verworfen.
- Nummerierungskonflikt A791-812 (2026-09-28).
  Nummern A791-794 waren in Doku-Commits 5caabea
  und baa011a vergeben. Die Auflagen der
  Punkt-32-Runde werden auf A813-A832 umbenannt.
  Kein Inhaltsverlust.
- Punkt 16a (bd7d187): gunicorn + ProxyFix.
  pyproject extra "prod", wsgi.py, ProxyFix,
  gunicorn.conf.py, systemd-Unit. Login-Rate-Limit
  jetzt pro Client (Punkt 27).
- Punkt 9 (c4a1fa0, 26e8176): Rate-Limit Multi-Worker.
  SQLite-basiert (chat_rate_hits, Migration 0009),
  BEGIN IMMEDIATE, Fail closed.
- Punkt 16b (b4a21e4): gunicorn control_socket_disable.
- Doku-Nachzug A589 (4d1c4cc): Chronologie neu
  sortiert, HEAD b4a21e4.
- Diagnose 2026-09-27 (96675da): Gesundheits-Check,
  dev-Dependencies nachinstalliert (ruff, mypy,
  pytest-cov), ruff 435 Fehler / mypy 87 Fehler
  als Bestandsaufnahme.
- UI-Feinschliff Teil 1 (61b739c, 37af0e1, 4ead797):
  SVG-Farben (#9ca3af), Spaltennamen anwenderfreundlich
  (alle 7 Listen), Sidebar-Namen (Freigaben, Aenderungen,
  Protokoll), Suchquellen-Namen (format_source_label).
- Punkt 30 (f737d3f): Links im Chat (fact/detail_append).
  core/context/links.py, API-Antwort 7 Schluessel.
- Punkt 29 (0ede98f): Wert-Synonyme fuer die Suche.
  synonyms.yaml, synonyms.py, SearchService-Erweiterung.
- 3.6.18a: risk_assessments.category durchsuchbar
  (Bugfix aus 3.6.16). Punkt 29 neu (Synonym-
  Mapping offen).
- Punkt 28 (a2b58c1): Dashboard-Chat bekommt Kontext
  (core/context/builder.build_chat_context). CLI und
  Dashboard nutzen denselben Builder.
  Verifikation: gunicorn --check-config OK,
  systemd-Start OK, HTTPS /login 200, POST mit
  falschem CSRF 400.
- Vorfall 2026-09-28: README.md durch cat >-Heredoc
  zerhackt (5b5a727). Erkennbar an Heredoc-Kopf
  ("cat > README.md << 'READMEEOF'", Zeile 1) und
  abgeschnittenem Ende ("- [Werk", 121 Zeilen).
  Repariert in e0a6aa4/4cc0a45. Ursache: TTY-Puffer
  bei langen Heredocs (WORKFLOW W2/W7a). Kein
  Sicherheitsvorfall, sondern Prozess-/Doku-Vorfall;
  kein neuer offener Punkt (A883).
- Vorfall 2026-09-28 (zweiter Heredoc-Fall): PROJECT_VISION.md
  begann mit der Heredoc-Kopfzeile
  ("cat > PROJECT_VISION.md << 'VISIONEOF'", Zeile 1).
  Anders als beim README-Vorfall (A883) kein
  abgeschnittener Inhalt: die Datei ist vollstaendig
  (676 Zeilen, Ende sauber bei "## 17. Referenzen").
  Reparatur: die Muell-Zeile entfernt (jetzt 675 Zeilen),
  Commit folgt.
  Ursache: derselbe Paste-/TTY-Puffer-Effekt wie A883
  (WORKFLOW W2/W7a). Kein Sicherheitsvorfall, sondern
  Prozess-/Doku-Vorfall.
  Praevention: Heredoc > ~3 KB nie in die interaktive
  Shell, Patch-Skripte in /tmp (WORKFLOW HR9).

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
   Erledigt in e45bc87 (Punkt 3, 2026-09-27):
   AccessService.create_principal prueft
   device.read und wirft AccessServiceError
   bei Rollen ohne device.read (Reviewer-GO
   Variante B, Auflagen 597-602). Doku in
   PERMISSIONS.md und DESIGN_DECISIONS §10.

4. `WEB_SECURITY_CHECKLIST.md` § E auf strenge
   CSP korrigiert (kein `'unsafe-inline'`) —
   Quelle jetzt `DESIGN_DECISIONS §16`.

5. ChatServiceError nicht in ServiceError-Hierarchie.
   Liegt in apps/security_ai/chat.py, erbt von
   RuntimeError. Route faengt nicht, globaler
   500. Eigener Aufraeum-Block: ChatServiceError
   -> OperationError (Auflage 87, 3.6.8e).
   Erledigt in 3.6.15c (f2fc220): ChatServiceError
   erbt jetzt von ServiceError. Neue Klasse
   ChatOperationError(OperationError) fuer
   Konstruktor-None und Audit-Ausfaelle. LLMError/
   LLMTimeout/LLMUnavailable bleiben roh (502,
   Auflage 487).

6. ApprovalService/InventoryService/
   AuditReaderService mischen Format- und
   Betriebsfehler in einer Klasse. Sollten auf
   ServiceError/OperationError-Trennung umgestellt
   werden (Vorbild: ChangeService, 3.6.8d).
   Eigener Aufraeum-Block.
   Erledigt in 3.6.15c (c3450c5, c7f2649, b0834d0):
   - InventoryService: InventoryOperationError neu.
   - AuditReaderService: AuditReaderOperationError neu.
   - ApprovalService: Repo-Fehler propagieren
     (Variante D, Auflagen 502-506). ApprovalNotFoundError
     -> 404, ApprovalStateError -> 409, Basisklasse
     ApprovalRepositoryError -> 500.

7. DESIGN_DECISIONS § 2 (tool-Tabelle):
   ChangeService -> change_service ergaenzen
   (Auflage 52, 3.6.8d).

8. DESIGN_DECISIONS § 11: Regel
   "Format-Fehler -> ServiceError-Subklasse -> 4xx.
   Betriebs-Fehler -> OperationError-Subklasse -> 5xx."
   ergaenzen (Auflage 74, 3.6.8d).

9 (erledigt, Commit c4a1fa0): Rate-Limit Multi-Worker.
   RateLimitService nutzt jetzt SQLite
   (chat_rate_hits, Migration 0009). Multi-
   Worker-fest, BEGIN IMMEDIATE, Fail closed
   bei SQLite-Fehler. Pro Request mit g.conn,
   Werte aus app.config CHAT_RATE_MAX/
   CHAT_RATE_WINDOW. Login-Rate-Limit bleibt
   unveraendert (login_attempts).
   Kategorie 3, Auflagen 663-676, Option B.

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
    Erledigt am 2026-09-28: sshd_config angepasst
    (PermitRootLogin prohibit-password,
    PasswordAuthentication no, PubkeyAuthentication yes).
    Key windows@... in /root/.ssh/authorized_keys.
    Backups: sshd_config.bak-20260928-095059 und
    sshd_config.bak-vor-punkt11.
    Tests von Windows: Key-Login OK, Passwort-Login
    -> Permission denied (publickey).

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
    Erledigt in 3.6.15b (a3589db): AuditWriter.write()
    legt neue Dateien mit os.open(mode=0o640) + os.chmod
    an und prueft bei existierenden Tagesdateien den
    Modus vor dem Schreiben (Fail closed, kein Silent
    Repair). Der Punkt bleibt hier als Referenz stehen.

14. Service-Start prueft audit-logs/ nicht auf Konsistenz
    (Owner, Modus, Fremddateien). Ein inkonsistenter
    Zustand wurde erst durch einen 500er sichtbar, nicht
    beim Start. Praevention: beim App-Start audit-logs/
    pruefen und bei Inkonsistenz fail closed oder warnen.
    Kategorie 2/3, eigener Block.
    Erledigt in 3.6.15b (a3589db): neue Modul-Funktion
    check_audit_logs(base_dir, expected_owner) prueft
    alle *.jsonl auf Modus 0o640 und Owner. create_app
    ruft sie mit check_audit=True vor check_schema_version
    auf. Fail closed via AuditDirInconsistentError.
    Der Punkt bleibt hier als Referenz stehen.

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
    (c) 1cedb26 (Fix D), (b) dd10214 (Fix C,
    DEPLOYMENT 3e + deploy/systemd/-Vorlage).
    Der Punkt bleibt hier als Referenz stehen.

16a (erledigt, Commit <hash>): gunicorn + ProxyFix.
    - pyproject extra "prod" mit gunicorn>=21.0.
    - apps/dashboard/wsgi.py (create_app(), kein
      __main__, kein Debug).
    - app.py: ProxyFix (x_for=1, x_proto=1, x_host=1).
      Nur, weil nginx der einzige vorgelagerte
      Proxy ist (Flask bindet 127.0.0.1:5000).
    - deploy/gunicorn.conf.py (2 Worker, 2 Threads,
      timeout 180, journal-Logging).
    - deploy/systemd/security-ai-dashboard.service:
      ExecStart auf gunicorn.
    - Tests: ProxyFix aktiv, wsgi.py-Quelltext.
    Kategorie 3, Auflagen 642-655.

16b (offen, wartet auf Betriebsakt): systemd-Start
    mit gunicorn verifizieren. gunicorn --check-config,
    curl /login, Login-POST, ss :5000. Wartet auf
    chown/chmod der zwei root:root-Dateien in
    audit-logs/ (25./26.09.), sonst fail closed.
    Kategorie 3, Auflagen 656-659.

17 (erledigt, Commit <hash>): Kein security_ai-Startpfad
    heute. check_schema_version dort nicht anwendbar.
    Siehe Punkt 26 (Startpfad fehlt).
    Kategorie 1 (Doku), Reviewer-Auflagen 398, 633.

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
    Erledigt in 0b970ec (Punkt 19, 2026-09-27):
    sieben Pro-Tabelle-Klassen (alerts, approvals,
    audit, changes, inventory, users, roles).
    Globales nth-child(n+4) ersetzt. Spaltenauswahl
    pro Tabelle mit Begruendung im CSS. 3 neue
    Tests. Reviewer-Auflagen 614-622.
    Betrifft sechs Tabellen (inventory, audit,
    users, changes, approvals, alerts).
    Eigener Folgeschritt nach 3.6.14.
    Kategorie 2, Reviewer-Auflage 419.

20. Muster: Test-Erwartungen werden durch gewollte
    Produktaenderung rot. Zwei Faelle in 3.6.14/3.6.15a:
    - test_inventory_version_gesetzt (Erwartung "0002"
      durch Fix A obsolet).
    - test_dashboard_alerts.py Badge-Mapping (Erwartung
      Rohkategorie durch Auflage 424 obsolet).
    Regel fuer die Zukunft: Wenn Tests rot werden, weil
    sich Produktverhalten gewollt aendert, ist der Test
    die Quelle der Wahrheit fuer das Verhalten, nicht
    fuer den Wortlaut. Test-Anpassung + Doku der
    Aenderung in einem Commit. Kategorie 2 mit Reviewer,
    wenn das Produktverhalten selbst Kategorie 3 war.
    Kategorie 1 (Doku), Reviewer-Auflage 435.

21. audit-logs/ 21.-25. Sep enthalten Burst-Eintraege
    aus OrchestratorTests (Bug in setUp, gefixt in
    3.6.15b, Commit a3589db). Analyse 2026-09-27:
    - 21.09.: 210 Burst-Sekunden (>=20 Eintraege/Sek),
      9053 von 9958 Eintraegen (91 %).
    - 22.09.: 176 Burst-Sekunden, 5759 von 7236 (80 %).
    - 23.09.: 38 Burst-Sekunden, 1291 von 1978 (65 %).
    - 24.09.: 14 Burst-Sekunden, 471 von 750 (63 %).
    - 25.09.: 30 Burst-Sekunden, 977 von 1508 (65 %).
    - 26.09. und 27.09.: 0 Burst-Sekunden.
    Feld-Marker (network_id, event_id-Format, audit_id,
    timestamp-Datum) sind unauffaellig. Eindeutig ist
    nur der Burst-Marker (>=20 Eintraege in derselben
    Sekunde, vollstaendige Orchestrator-Kette pro
    Event).
    Verfaelschung: Dashboard-Kacheln, /audit, /alerts
    (24h-Fenster nur an den Tagen selbst), 3.6.16-Suche
    (risk_assessments) zaehlen die Burst-Eintraege mit.
    Kein Eingriff in audit-logs (append-only).
    Dokumentiert in audit-logs/README.md.
    Kategorie 3, Reviewer-Auflagen 477, 627-631.

22. Sanity-Check hat in 0 von 14 kritischen Faellen
    gefeuert (gemessen am 2026-09-26 vor 3.6.15d).
    Ursache pruefen: Erkennungslogik, Kontext-Handling
    oder Pattern-Matching. Nach 3.6.15d sind die
    Auto-Switch-Faelle seltener geworden (F1-F3), daher
    ist eine Neumessung noetig. Eigener Block,
    Kategorie 3, Reviewer-Auflage 510/511/518.
    Erledigt in der Neumessung 2026-09-26 (25 Fragen):
    - chat_answer_contradicts_context: 2 (vorher 0/14).
    - llm_retry: 0 (korrekt: die 2 Faelle waren bereits
      auf qwen2.5:7b, Retry greift nur bei 3B).
    - Auto-Switch: 10 von 15 LLM-Faellen auf 7B.
    - Concept: 5 von 5 auf 3B (unveraendert).
    - Fact-Pfad: 9 Fragen deterministisch, kein LLM.
    Der Sanity-Check funktioniert nach 3.6.15d wie
    beabsichtigt. Kein weiterer Fix noetig.

23. Audit-Konsistenz: chat_answered-Eintraege im
    Audit-Log haben model_reason=null, obwohl die
    ChatResponse den Wert korrekt traegt
    (fact / detail_append / no_context).
    Ursache: _log("chat_answered", ...) uebergibt
    model_reason nur im LLM-Pfad, nicht im fact-,
    detail- oder no_context-Pfad.
    Auswirkung: Audit-Verteilung ist unvollstaendig;
    die 9 fact- und 1 detail_append-Faelle aus der
    Punkt-22-Messung erscheinen als model_reason=None.
    Kategorie 2, eigener Block.
    Erledigt in dccebf1: _log("chat_answered", ...)
    uebergibt model_reason jetzt in allen drei
    Pfaden (fact, detail_append, no_context).
    Drei neue Tests in tests/unit/test_chat.py.

24. Wenn assign_role im AccessService gebaut wird:
    device.read-Pruefung ebenfalls dort. Heute kein
    assign_role, kein Handlungsbedarf.
    Kategorie 2, Auflage 597.

25. Audit-Eintraege aus Testlaeufen sind im Dashboard
    nicht von echten Events unterscheidbar. Eine
    zuverlaessige Unterscheidung ist heute nicht
    moeglich (kein Marker). Kuenftige Praevention:
    alle Test-Audits in tmp-Pfade schreiben (seit
    3.6.15b implementiert). Eine nachtraegliche
    Markierung im Dashboard ist nicht geplant.
    Kategorie 3 (Audit/Nachweis-Integritaet).
    Kein Bau heute.

26: security_ai-Startpfad fehlt komplett. Kein
    __main__.py, keine systemd-Unit, kein
    Start-Skript. Der Orchestrator wird heute
    manuell gestartet. Wenn der Startpfad gebaut
    wird: systemd-Unit (analog
    security-ai-dashboard.service), __main__.py,
    check_schema_version und Reviewer-Block.
    Kategorie 3, eigener Block.

27 (erledigt, bd7d187): Login-Rate-Limit nutzte
    request.remote_addr (= 127.0.0.1 hinter nginx).
    5 Fehlversuche sperrten global, nicht pro Client.
    Fix: ProxyFix (Punkt 16a). Verifikation in 16b.
    Kategorie 3, Auflagen 650.

28 (erledigt, a2b58c1): Dashboard-Chat hatte keinen
    Kontext (seit 3.6.8e). routes_chat.py rief
    ChatService.ask nur mit principal/question/detail.
    Folge: Chat sagte immer "keine Daten". Fix:
    neues Modul core/context/ mit build_chat_context.
    CLI und Dashboard nutzen denselben Builder.
    Kategorie 3, Auflagen 719-728, Variante C.

30. Links im Chat: fact/detail_append-Antworten
    liefern jetzt eine strukturierte Link-Liste
    (label, href) an das Frontend. Sicherheit:
    nur interne Pfade (Whitelist), RBAC pro Link,
    kein Href aus dem Text. LLM-Antworten werden
    nicht verlinkt. API-Antwort hat jetzt 7 Schluessel
    (links neu, A768). Modul core/context/links.py.
    Kategorie 3, Auflagen 757-772, Variante 4.

31. (erledigt, 7a92b54) Fact-Antwort-Stil: Anzeige-Anker
    (Zeitraum, Begriff "Alarme" statt "Assessments",
    optional Link auf /alerts). Eigener Block.
    Erledigt in 7a92b54 (Auflagen 821-854), Teil 1+2:
    - CATEGORY_LABELS in core/risk/models.py (A823).
      filters.py importiert von dort.
    - _answer_fact nutzt _label(cat) und
      _ORDERED_CATEGORIES (A821/A824).
    - "Assessments" -> "Vorkommen" (A825).
    - ContextBundle.since_hours (A837), durchgereicht
      von ChatService.ask (A844/A845) und
      ContextBuilder.build (A846).
    - _format_hours (A839) fuer dynamischen Zeitraum.
    Teil 3 (Link auf /alerts) als Punkt 33.

33. (erledigt, 7b234df) Fact-Pfad liefert keinen Link auf /alerts.
    extract_links (Punkt 30) erkennt nur IDs (AUD, CHG,
    APR, IPv4) und laeuft nur in apps/dashboard/
    routes_chat.py, nicht im ChatService. Die Link-
    Whitelist enthaelt /alerts/ nicht. Wenn ein
    Navigations-Hinweis auf /alerts gewuenscht ist:
    eigener Block mit Bestandsaufnahme, wie der Link
    transportiert wird (Text-Marker, separates Feld,
    oder Route-Hinweis). Kein Markup im Text.
    Erledigt in 7b234df (Auflagen 858-881), Option A:
    - _answer_fact gibt (answer, kind) zurueck (A873/A874).
    - ChatResponse.nav_links (A876).
    - ask()-Fact-Zweig setzt nav_links nur bei
      fact_kind == "auff_ja" UND alert.view (A875/A866).
    - API-Antwort 8 Schluessel (A862/A878).
    - chat.js renderNavLinks (A879).
    - _ALLOWED_EXACT = ("/alerts",), exakter Match,
      /alerts/foo bleibt verboten (A880).

32. (erledigt, 213ab7b) Klassifikations-Luecke: "Gibt es X?"
    matcht nicht _FACT_RE (nur "gab es"). Solche
    Fragen landen im Interpretations-Pfad statt
    im Fact-Pfad. Kategorie 3, eigener Block.
    Erledigt in 213ab7b (Auflagen 804-811): _FACT_RE
    um "gibt es" / "gibts" / "gibt's" erweitert.
    Veto gegen Bewertungsworte (A792-Liste) in
    _classify_question (A809). Neue Konstante
    _CRITICAL_STATE_WORDS (A805) und Funktion
    _has_critical_state_word (A806/A810).
    _is_state_question, _answer_fact, Auto-Switch
    und model_reason unveraendert.

29 (erledigt, 0ede98f): Synonym-Mapping.
    Variante 2 (Werte-Synonyme). Neue Datei
    core/search/synonyms.yaml, neues Modul
    core/search/synonyms.py (load_synonyms,
    expand_query). SearchService erweitert
    Suchbegriffe auf Synonym-Zielwerte.
    Keine Quellen-Synonyme (Variante 1 verworfen).
    Kategorie 3, Auflagen 776-790.

34. (offen) sudo fehlt auf CT102. Nicht-Root-SSH
    nicht moeglich (kein sudo). Wenn ein
    Nicht-Root-Nutzer SSH nutzen soll: apt install
    sudo + sudoers-Konfiguration. Eigener Betriebsakt,
    Kategorie 1 (Doku + Betrieb). Kein Reviewer-Block.
    Anlass: Befund 2026-09-28 bei Punkt 11 (SSH Key-only).

- Backup-Bestaende (2026-09-28, A884/A885): kein
  Loeschen jetzt. Beim naechsten Aufraeumen pruefen:
  /etc/ssh/sshd_config.bak-20260928-095059,
  /etc/ssh/sshd_config.bak-vor-punkt11,
  /root/.ssh/authorized_keys.bak,
  /root/.ssh/authorized_keys.bak2 (enthaelt eine
  ungueltige Fingerprint-Zeile aus alter
  Paste-Verwechslung; sshd ignoriert sie).

35. (erledigt, b3db49c) mypy method-assign app.py:64 (app.wsgi_app = ProxyFix(...)).
    # type: ignore[method-assign] mit Kommentar,
    Flask-/Werkzeug-Idiom, kein alternativer Weg.
    Flask-Attribut wird von mypy als Methode gesehen.
    Kein Laufzeitfehler heute. Fix waere ProxyFix anders
    anwenden (z. B. app.wsgi_app = ProxyFix(...) mit
    # type: ignore[method-assign] oder anderer Aufbau).
    Eigener Block, Kategorie 3.
    Hinweis: urspruenglich app.py:67, durch Lint-Runde
    auf 64 verschoben.

36. (erledigt, 809e861) DetectionEngine.list -> list_rules.
    Methode umbenannt. Kein Aufrufer ausserhalb der
    Definition. 4 # type: ignore[valid-type] in engine.py
    entfernt. 2 # type: ignore[attr-defined] in
    orchestrator.py entfernt (mypy: unused-ignore; der
    Kommentar war schon vorher falsch). mypy engine.py:
    Success. Tests: 2 neue Smoke-Tests fuer list_rules.
    Kategorie 3.

37. (erledigt, 75b5ec1) ApprovalRequired.tool_args statt .args.
    (Ur-Text: ApprovalRequired.args ueberschreibt
    BaseException.args. self.args = args setzt ein dict
    ueber das tuple der Basisklasse (Semantik-Konflikt,
    nicht nur mypy). Umbenennen in tool_args
    (eigener Block, Kategorie 3).

38. (erledigt, 2bdc16b) redact_mapping-Signatur korrigiert (dict[str, Any]).
    (Ur-Text: redact_mapping-Signatur ist zu eng
    (dict[str, str] statt dict[str, Any]). Der Aufrufer
    in harness/context/builder.py weist list[str] zu,
    mypy meldet assignment. Signatur richtig stellen
    (eigener Block, Kategorie 3).

- Lint-Bestandsaufnahme (2026-09-28, A905/A921):
  ruff vorher 452, nachher 122. Auto-Fix-Kategorien
  I001 (151), UP017 (98), kleine Gruppen (85),
  F401 (88) abgearbeitet. mypy vorher 89, nachher 80;
  echte Typfehler 15 -> 6 (Gruppe 2+3, Punkte
  35/36/37/38 und die drei Bug-Kandidaten).
  Reste: C408 (22), BLE001 (18), SIM117 (17),
  TRY004 (17), RUF015 (15), S110, DTZ001, SIM102 u. a.
  -- nicht auto-fixbar, eigener Reviewer-Block (A901).
  no-untyped-def (67) -- eigene Runde (A900).
  method-assign app.py:67 -- Punkt 35, eigener Block.

39. (erledigt, c1d2fe2) role.row_id None fail closed.
    init_db.py:182 und access_service.py:192 pruefen
    vor dem create-Aufruf, klare Fehlermeldung statt
    generischem AccessRepositoryError.

40. (erledigt, c05283e) _validate_len getrennt in
    _require_len/_optional_len. Annotation statt
    str | None. Kein Verhalten geaendert.

41. (erledigt, 01466e0) apps/dashboard/decorators.py:32 attr-defined.
    Regression durch B010-Auto-Fix in 3b20891:
    setattr(fn, "_required_permission", code) wurde zu
    fn._required_permission = code. F ist TypeVar(
    bound=Callable), direkte Zuweisung nicht moeglich.
    setattr zurueck + # noqa: B010 mit Begruendung.
    Notiz: B010-Auto-Fix ist nicht in allen Faellen
    korrekt (TypeVar-gebundene Callables).
    Ur-Text: apps/dashboard/decorators.py:32
    attr-defined. Regression durch B010-Auto-Fix
    in 3b20891: setattr(fn, "_required_permission",
    code) wurde zu fn._required_permission = code.
    mypy sieht F (TypeVar) ohne Attribut.
    Fix-Vorschlag: setattr zurueck + # noqa: B010
    (B010 nicht anwendbar, weil F kein konkreter Typ).
    Eigener Block, Kategorie 3 (Dekorator/Flask-Setup).

42. (erledigt, Commit siehe Chronologie) Identifier-Schema MAC.
    Bestandsaufnahme: devices + device_history sind leer
    (0 Zeilen). Keine Migration noetig. identifier bleibt
    TEXT (MAC passt rein). nmap liefert heute keinen
    identifier (nur ip im parser). nmap produziert heute
    keine device_presence-Events. Der MAC-Umstieg wirkt
    im Fritz!Box-Watcher (Block 3.8a) — der Watcher setzt
    identifier=MAC.
    Punkt 42 selbst = neue Tests (tests/unit/
    test_identifier_mac.py, 4 Tests) + Doku. Kein
    nmap-Patch, kein Schema-Wechsel.
    Kategorie 3.

43. (Beobachtungsstand 2026-10-01) MAC-Randomisierung.
    ERNEUTER BEFUND 2026-10-01: derselbe Hostname
    "S25-von-A" erscheint mit drei MACs im Inventory:
    - E2:A3:48:2B:07:4C (Hauptnetz, aktiv)
    - 82:E1:00:82:16:96 (Gastnetz, aktiv)
    - 6A:32:F0:D4:FE:D2 (inaktiv, letzte IP
      192.168.178.50)
    Grund: das Handy vergibt pro Netz-Assoziation
    eine neue MAC (Private WLAN-Adresse).
    Vorheriger Stand (2026-09-28): 1 von 6 Geraeten
    randomisiert, kein Hostname-Konflikt.
    Kein Handlungsbedarf heute.
    Beobachten:
    - Waechst die Zahl randomisierter MACs?
    - Erscheint derselbe Hostname mit mehreren MACs?
    - Gibt es doppelte Geraete im Inventory?
    Wenn ja: eigener Block, Kategorie 3,
    Policy-Entwurf.
    Kein vorsorglicher Filter (A1273): der Watcher
    sendet weiter device_presence, der Orchestrator
    nimmt weiter ins Inventory auf, Detection-Regeln
    unveraendert.
    Nutzer-Option (A1274): randomisierte MAC in die
    Whitelist aufnehmen, wenn das Geraet vertraut ist.
    Kategorie 1 (Doku), kein Bau.
    EMPFEHLUNG 2026-10-01: an den betroffenen Geraeten
    die MAC-Randomisierung fuer das jeweilige WLAN
    deaktivieren (iOS: "Private WLAN-Adresse: Aus";
    Android: "Zufaellige MAC: Aus"). Damit hat jedes
    Geraet pro Netz eine stabile MAC. Kein Code-Aufwand,
    behebt die Mehrfach-Eintraege an der Wurzel.
    Wenn weiterhin mehrere MACs pro Geraet gewuenscht
    sind: eigener Kategorie-3-Block
    (Hostname-basierte Identitaet oder Alias-Tabelle).

44. (entfallen, A1125/A1126) Fritz!Box-Host-Status.
    Der status-Key in get_hosts_info ist bool
    (NewActive) laut fritzconnection-Code/Doku.
    Damit keine unverifizierte Wette, kein
    offener Punkt. Der Watcher kapselt bool(status)
    defensiv.

45. (offen) Verwaiste .env.example-Variablen
    (Namen ohne Code-Nutzung). Liste:
    ADMIN_AI_API_KEY, ADMIN_AI_MODEL, ADMIN_AI_PROVIDER,
    BIND_HOST, DASHBOARD_PASSWORD, DASHBOARD_PORT,
    DASHBOARD_USER, GUEST_NETWORK_PREFIX,
    NETWORK_WATCH_ENABLED,
    PORTSCAN_THRESHOLD_IPS, PORTSCAN_THRESHOLD_IPS_WINDOW,
    PORTSCAN_THRESHOLD_PORTS, PORTSCAN_THRESHOLD_WINDOW,
    PROXMOX_TOKEN_ID, PROXMOX_TOKEN_SECRET, PROXMOX_URL,
    PROXMOX_VERIFY_SSL, SNIFF_IFACE, WEBHOOK_PORT,
    WEBHOOK_TOKEN.
    Kein Loeschen ohne Nutzer-Entscheidung. Viele
    legitim fuer spaetere Phasen (PROXMOX_* Phase >5,
    TELEGRAM_* heute genutzt, SNIFF_IFACE/PORTSCAN_*
    Phase 3.8b, ADMIN_AI_* Phase 5).
    Kategorie 1 (Doku).

46. (erledigt in 4a03310) Event-Datei-Modus 640.
    tools/fritzbox_watcher.py::_write_events legt neue
    Event-Dateien mit Modus 0o640 an (os.open +
    os.chmod), konsistent zu audit-logs. State-Datei
    bleibt 600 (Netzwerk-Topologie, vertraulicher).
    Variante A (A1254): bestehende Event-Dateien werden
    NICHT geprueft/repariert. Bestehende
    data/events-2026-09-28.jsonl bleibt 644; neue
    Tagesdateien sind 640. Betriebsakt (chmod) optional.
    Kategorie 2.

- 3.6.18b (7a92b54): Fact-Antwort-Stil. Labels statt
  Rohkategorien, dynamischer Zeitraum, "Vorkommen".
  Punkt 31, Auflagen 821-854.
- Punkt 33 (7b234df): nav_links im Fact-Pfad.
  Auffaelligkeits-Antwort -> /alerts. API 8 Schluessel.
  Auflagen 858-881.
- Punkt 28 (a2b58c1): Dashboard-Chat-Kontext
  (core/context/builder.build_chat_context).
- Punkt 11 (d1602ef): SSH Key-only. Betriebsakt.
  PermitRootLogin prohibit-password,
  PasswordAuthentication no.
- Punkt 32 (213ab7b): Klassifikations-Luecke "gibt es".
  _FACT_RE erweitert, Veto gegen Bewertungsworte.
- Zwischenblock Lint/Typen (540b205, 3a5dbab, 6426967,
  d6ecc01, 3b20891, 6ec5c12, 9697c22, c1d2fe2,
  c05283e, 2bdc16b, 75b5ec1, b3db49c, 01466e0):
  ruff 452 -> 122, mypy 89 -> 71, echte Typfehler
  15 -> 0. Gruppe 2+3 (5 Fixes). Punkt 41
  (B010-Regression) gefunden und behoben.
- Doku-Nachzug README + PHASES (e0a6aa4, 4cc0a45,
  8e79495): README-Heredoc-Vorfall repariert,
  Kernzahlen 950, PHASES 3.6.10/3.6.11 abgehakt.

26. (erledigt in 02f17c4, 468a14d, Commit 5) security_ai-Startpfad.
    Neue Migration 0011 (processed_events).
    SecurityAI(skip_migrations=True).
    tools/event_reader.py: liest data/events-YYYY-MM-DD.jsonl,
    ruft SecurityAI.process() pro Event, Cursor in DB
    (event_cursor), Idempotenz-Marker in DB
    (processed_events). Fail closed (Exit 1-4).
    systemd-Timer security-ai-event-reader.timer (30s).

47. (erledigt, f256d83) processed_events-Aufraeumen.
    Im event_reader.run() nach der Event-Schleife:
    DELETE FROM processed_events WHERE processed_at <
    (now - 30 Tage). Konstante PROCESSED_EVENTS_MAX_AGE_DAYS
    = 30 im Modul. Eigene kurze Transaktion, kein VACUUM,
    kein Audit. Log INFO nur wenn > 0.
    Aufraeum-Fehler: Log ERROR, run() returnt 0
    (Hauptzweck Events verarbeiten ist erfuellt).
    Kategorie 2.

48. (erledigt, 58ea5ad) IP im Inventory fehlt.
    Watcher liefert ip in data['ip'], Orchestrator
    hat sie verworfen. Fix: Migration 0012
    (devices.last_ip), Device.last_ip, upsert_seen
    (ip=None), _update_inventory reicht ip durch,
    inventory_detail.html zeigt IP (Fallback "—").
    Kontext-Feld, keine Identitaet: identifier (MAC)
    bleibt die Identitaet.
    Kategorie 2.

49. (offen, Kategorie 1) last_ip wird nur bei Events
    gesetzt, die durch den Diff erzeugt werden.
    Bestehende Geraete haben last_ip=NULL, bis sie
    das naechste Mal in einem Event erscheinen
    (device_presence bei neuem Geraet oder
    aktiv-Werden). Bewusst nicht nachtraeglich
    gefuellt. Wenn ein Backfill aus der Event-
    Historie gewuenscht ist: eigener Block.

51. (erledigt, c8f1f49) DTZ007 + PERF402 in
    audit_reader_service.py.
    DTZ007 (2x): datetime.strptime(date_str, "%Y-%m-%d")
    -> date.fromisoformat(date_str). Reines Datum ohne
    Zeit; %z nicht anwendbar. Z. 76: datetime.combine
    (date.fromisoformat, time.min, tzinfo=UTC).
    PERF402 (1x): for-Schleife mit append -> extend.
    Kategorie 3 (produktiver Kern-Service).

53. (erledigt 2026-09-29, Doku) ruff-Config.
    Bestandsaufnahme mit `ruff check --show-settings`:
    ruff 0.16.9 Default-Satz ist breit (~200+ Regeln),
    enthaelt BLE001, DTZ001, B010, S110, G201, RUF100.
    `ruff check .` prueft alles, `ruff check . --statistics`
    ist der reproduzierbare Stand.
    `ruff check . --select RUF100` war ein forcierender
    Aufruf (RUF100 gegen ALLE # noqa, auch wo die
    Regel triggert), kein Config-Bug.
    Konsequenz: kein pyproject-Eingriff, Config bleibt
    unveraendert.

53b. (offen) ruff-Regelschaerfung.
     Kandidaten: PL (pylint), TRY (tryceratops),
     ANN (annotations), S (bandit), T20 (print),
     ARG (unused-arg).
     Eigener Block, Kategorie 3.
     Vorher: Bestandsaufnahme pro Regel-Gruppe.
     Nicht heute.

54. (offen, Kategorie 1 / Betriebsakt) Capability-Abgleich
    CT102 (lxc.cap.drop).
    - SECURITY.md § 5.2 beschreibt die Ziel-Werte fuer
      lxc.cap.drop (net_raw net_admin sys_admin
      sys_module sys_ptrace).
    - Der real gesetzte Wert liegt in
      /etc/pve/lxc/102.conf auf dem Proxmox-Host.
    - Von CT102 aus nicht messbar.
    - Betriebsakt: cat /etc/pve/lxc/102.conf
      (Host-Zugriff erforderlich). Ergebnis in § 5.2
      nachziehen oder als Ist-Stand-Absatz ergaenzen.
    - Kategorie 1, Doku-Nachtrag nach Messung.

55. (erledigt, Kategorie 2 + 3, Dashboard) Anzeige-
    Erweiterung Dashboard (Live).
    - T1 Live-Geraeteuebersicht auf /: Kachel
      "Geraete N" ersetzt durch Live-Info
      "welche Geraete sind jetzt online" + letzte
      5 Geraete, Namen, klickbar fuer Detailseite.
    - T2 Geraetedetailseite Netzwerk-Zeile:
      Hauptnetz / Gastnetz.
    - T3 Gast/Haupt getrennt auf /.
    - T4 Diagramme Systemstatus: RAM, CPU,
      "letzte Logs mit Aenderungen".
    - T5 Alarme-Seite: letzte 5 Alarme immer
      sichtbar, neuer Alarm sofort ersichtlich.
    - T6 Kacheln klickbar -> Filter-Seiten mit
      mehr Anzeige (z. B. /inventory?filter=active,
      /alerts?since=24h).
    - Technologie Live offen (WS/SSE/Polling).
    - Kein Code ohne Reviewer-Block (Kategorie 3).
    Erledigt in Punkt-55-Block (7 Commits,
    2026-09-30 bis 2026-10-01, HEAD d607d82):
    - e0b60f8 Layout-Fix .dashboard-grid/
      .stat-cards.
    - 876e7c7 T2 Netz-Label (network_label()).
    - 397a551 T3 Gast/Haupt (count_by_network,
      SQL GROUP BY).
    - 3e2d354 T6 Kacheln klickbar (<a>-Wrapper,
      .card-link).
    - 2d3223c T1+T5 Live-Geraete + Live-Alarme
      (FritzboxStateService, /api/dashboard/state,
      dashboard.js Polling 5s/30s).
    - 36ef968 T4 System-Sparklines + Logs mit
      Aenderungen (list_recent_by_kinds,
      eigenes SVG-Rendering).
    - d607d82 B5 Verwaltung details/summary.
    Tests: 1040 -> 1071.
    Live-Technologie: Polling (kein WS/SSE).

56. (offen, Kategorie 3, Dashboard-Aktionen)
    Schreiboperationen auf Kern-Daten.
    - A1 Detailseite: auf Whitelist setzen.
    - A2 Detailseite: Geraet blockieren
      (Zugang zu Netz UND Server verweigern).
      Neues Harness-Tool (block_device),
      Level 4, Approval-Pflicht, Rollback-Plan.
    - A3 gestrichen (whoami).
    - A4 Detailseite: Tracing-Link (whois +
      traceroute), zwei neue Tools, Level 1,
      scope_guard-pflichtig.
    - A5 Detailseite: History-Button.
    - A6 Uebersicht: Schnellblock bei Angriffen.
    - Kurze Wege: Aktionen auf Detailseite und
      pro Zeile in Live-Listen.
    - Change Request Pflicht bei allem Level 2+.
    - Bestaetigungsdialog ist die einzige
      Schnittstelle zwischen Bedienung und Wirkung.
    - Kategorie 3 pro Aktion.

57. (offen, Kategorie 3, Guardrails-Reiter)
    - G1 Guardrails-Liste mit Aktivierungsstatus.
    - G2 Aktivieren/Deaktivieren via Change
      Request (nicht direkt). Doppelte Bestaetigung
      (UI-Anlage + Freigabe).
    - G3 Feineinstellungen pro Guardrail.
    - Voraussetzung: Change-Request-Applier fuer
      Guardrail-Aenderungen (existiert heute nicht,
      harness/versioning/applier.py ist Stub).
    - Offene Klaerungen: Parameter-Modell,
      Persistenz, Reload-Semantik, Permission
      guardrail.manage.
    - Kategorie 3.

58. (offen, Kategorie 3, Werkzeuge-Werkbank)
    Read-only-Werkbank im Dashboard mit Untermenues.
    Drei Runden:
    - Runde 1 (read-only, Level 0-1):
      ping, traceroute, whois, dns_lookup,
      port_check, system_status, service_status,
      disk_usage, network_interfaces, audit_tail,
      event_tail, device_history, scan_history.
    - Runde 2 (Aktionen, Level 2-4):
      block_device, unblock_device, whitelist_add,
      whitelist_remove, firewall_rule_*.
    - Runde 3 (sehr invasiv, nur mit Design):
      fritz_*, proxmox_*, change_deploy.
    - Aufrufweg: UI -> Service -> AgentLoop ->
      Harness -> Tool. Kein direkter Tool-Aufruf.
    - Kategorie 3 pro Runde.

59. (offen, Kategorie 3, Betriebsparameter-Reiter)
    Schwellenwerte justierbar machen.
    - Rate-Limit (WINDOW_SECONDS, MAX_REQUESTS).
    - Session-Timeout.
    - Risk-Schwellen (heute in core/risk/rules.yaml).
    - Login-Rate-Limit.
    - Aenderungen via Change Request.
    - Kategorie 3.

60. (erledigt, Kategorie 3, Kern-Service) mypy
    no-untyped-def in apps/security_ai/orchestrator.py.
    - Z. 266: Function is missing a return type annotation.
    - Z. 318: Function is missing a type annotation for one
      or more parameters.
    - Vorbestehend, durch A900-Typisierung sichtbar
      geworden (mypy folgt Import-Pfaden tiefer).
    - Nicht durch A900 eingefuehrt.
    - Erledigt in B1b-2 (Commit d93cc68, 2026-09-30):
      create_change_request -> ChangeRequest;
      _notify_approval audit_fn -> Callable[..., None].


61. (offen, Kategorie 1 Messung + Kategorie 3
    Fixes, Sicherheits-Lint) ruff -S
    (flake8-bandit) Bestandsaufnahme.
    - S ist heute nicht im Default-Lauf aktiv.
    - Verhaeltnis zu 53b: 61 ist der Vorlauf fuer
      die S-Gruppe aus 53b. Kein Ersatz, keine
      Nachfolge. 53b bleibt Sammelpunkt fuer PL,
      TRY, ANN, S, T20, ARG.
    - Prueft: subprocess ohne shell=False,
      eval/exec, hartkodierte Secrets, weak
      crypto, unsichere Temp-Files, binding
      auf 0.0.0.0, assert in Produktivcode.
    - Ablauf:
      1. Bestandsaufnahme (Kategorie 1):
         ruff check . --select S --statistics
         ruff check . --select S --output-format concise
      2. Auswertung pro Treffer.
      3. Fixes pro Gruppe (Kategorie 3, eigener
         Reviewer-Block).
    - Anlass: A900-2b-2c-Vorfall (zwei I001-
      Regressionen durch Import-Nachtraege, erst
      durch ruff-Nachmessung entdeckt). S ist die
      naechste Messluecke.
    - Kein Code in Schritt 1 (nur Messung).
    - Messergebnis 2026-09-30 (HEAD b86cc40):
      896 Treffer gesamt, 8 Regeln.
      - 869 S101 (assert in tests/): Fehlalarm.
      - 25 S105/S106/S108 (Test-Fixtures):
        Fehlalarm, muss pro Datei geprueft werden.
      - 3 echte Kandidaten (Kategorie 3):
        - S608 core/changes/repository.py:313, 361
        - S603 tools/nmap_scan.py:315
        - S314 tools/nmap_scan.py:222
      - Naechster Schritt: (c) Tests-Rauschen
        stumm schalten, dann (b) Kandidaten
        verifizieren.
      - S wird NICHT in den Default-Satz
        aufgenommen, solange das Rauschen
        nicht unterdrueckt ist (sonst ist jeder
        ruff-Lauf unlesbar).

    - Korrektur 2026-09-30 (HEAD 35e25a4):
      Die urspruengliche Klassifikation war
      ungenau.
      - S101: nicht alle in tests/. Zwei
        Fundstellen in core/inventory/:
        - core/inventory/repository.py:319
        - core/inventory/whitelist.py:139
      - S105: eine Fundstelle nicht in tests/:
        - harness/context/redaction.py:32
      - S310 (nicht im Bericht erwaehnt):
        3 Fundstellen in harness/llm/client.py.
      - Nach den korrigierten Zahlen:
        896 Treffer minus 867 S101 (in tests/)
        minus 24 S105/S106/S108 (in tests/)
        = 3 S-Kandidaten aus dem Erstbericht
        plus 6 zusaetzliche = 9 Kandidaten.

62. (abgeschlossen, Kategorie 3, Sicherheits-Lint)
    ruff -S verbleibende Treffer verifizieren.
    - Aus Punkt 61 Messergebnis (HEAD b86cc40,
      korrigiert 2026-09-30).
    - Nach per-file-ignores tests/*:
      Stand HEAD 2ab53dd: 6 Treffer aus 5 Regeln.
    - Erledigt:
      - S101 core/inventory/repository.py:319
        -> Commit 1, assert -> InventoryRepositoryError.
      - S101 core/inventory/whitelist.py:139
        -> Commit 2, analog.
      - S105 harness/context/redaction.py:32
        -> Commit 3, _REDACTION_TOKEN ->
        _REDACTION_PLACEHOLDER.
      - S314 tools/nmap_scan.py:222
        -> Commit 4, defusedxml.
    - Bewusst offen (mit Begruendung):
      - S310 harness/llm/client.py:101, 109, 184:
        Scheme-Check existiert im Konstruktor
        (client.py:53-62). Loopback-Pruefung liegt
        in core/config.py:validate_ollama_base_url
        (neu, Fix 5, Commit 2ab53dd). Der Client
        bleibt kontextfrei, Validierung ist
        upstream. Kein noqa (S310 ist nicht im
        Default-Satz, noqa waere RUF100).
      - S608 core/changes/repository.py:313, 361:
        sets aus festen Spaltennamen bzw.
        _UPDATABLE_FIELDS-Whitelist. Werte als
        ?-Parameter. Kein noqa (S608 nicht im
        Default-Satz, waere RUF100).
      - S603 tools/nmap_scan.py:316:
        subprocess.run mit shell=False explizit.
        Kein noqa (S603 nicht im Default-Satz,
        waere RUF100).
    - Abgeschlossen am 2026-09-30 (HEAD b86cc82).
      S-Treffer im Projekt: 6 aus 5 Regeln, alle
      bewusst offen mit Begruendung. Fix 6 (noqa)
      entfaellt: S608/S603/S310 sind nicht im
      Default-Satz, noqa waere RUF100.
63. (erledigt, Kategorie 1 + 2 + 3, Typen)
    mypy 37 Fehler in 15 Dateien (Stand HEAD
    58b039e, 2026-09-30).
    Handoff nannte 2 (Punkt 60). Gemessen 37.
    - 15 arg-type: str | None ungeprueft an
      Service. Fix: Route validiert None ->
      400/redirect (fail closed am Rand).
    - 12 return-value: redirect() liefert
      werkzeug.Response vs. flask.Response.
      Fix: cast(Response, redirect(...)) oder
      Helper _redirect(url).
    - 7 import-untyped: yaml, defusedxml,
      fritzconnection. Fix: types-PyYAML,
      types-defusedxml als dev-deps,
      fritzconnection: ignore_missing_imports.
    - 2 no-untyped-def: Punkt 60
      (orchestrator.py).
    - 1 no-redef: agent_loop/loop.py:451
      (Bestandsaufnahme vor Fix).
    Aufteilung: B1a (app.py, Kategorie 3),
    B1b (Kern-Services, Kategorie 3),
    B1c (Tools, Kategorie 2),
    B1d (Stubs, Kategorie 1).
    Erledigt in B1 (HEAD 2de4a40, 2026-09-30):
    mypy 37 -> 0. B1c entfiel (durch B1d behoben).


- Phase 3.8a: Fritz!Box-Watcher (e4d032e, e7a669e,
  22ad6d5, 8eb9772, 50daee8). Producer fuer
  device_presence/offline. identifier=MAC.
  Migration 0010 (event_cursor). Extra fritzbox
  in pyproject. systemd Timer + Service.
  Punkt 42 (MAC-Identifier) erledigt. Punkt 43
  (MAC-Randomisierung) neu offen.

- Block Dashboard-Kacheln (e6aec9c):
  Route / liefert Live-Werte (device_count,
  alert_count, approval_count, change_count).
  index.html: alle vier Kacheln conditional
  per can_view_*. Fallback "—" bei Service-
  Fehler oder fehlender Permission (L2).
  Ticket 3.6.7d abgeschlossen.

Core-Stand 2026-09-30: HEAD 2de4a40, 1040 Tests,
mypy 0, ruff 0 (B1 abgeschlossen, 15 Commits, 37 -> 0).
A900 abgeschlossen (23 Commits, 66 -> 2).

## A900 - no-untyped-def (Kategorie 2 + 3)

Status: [x] abgeschlossen (HEAD 81a3607, 2026-09-30).
Kurzfassung: mypy no-untyped-def 66 -> 2, ruff 2 -> 0,
23 Commits, Tests durchgehend 1028 gruen.

Aufschluesselung:

A900-1 (Kategorie 3, 4 Commits, mypy 66 -> 55):
  22ead01  search_service.py _search_with_synonyms
  8fe36e4  chat.py generate/_call_llm/_format_*
  27a182d  approval_service.py _entry_to_dict
  67103c8  change_service.py _log **extra

A900-2a (Kategorie 2, 3 Commits, mypy 55 -> 51):
  40cfeb9  audit_reader.py _iter_jsonl_lines
  3b8758d  changes_cli.py _audit **extra
  6a1747c  chat_cli.py _print_response/_load_context

A900-2b-1 (Kategorie 2, 2 Commits, mypy 51 -> 33):
  e50e2c6  auth.py 8 Funktionen
  68fcff6  app.py create_app + 7 Callbacks

A900-2b-2a (Kategorie 2, 2 Commits, mypy 33 -> 23):
  3180e4a  routes_users.py 6 Handler
  9690b03  routes_roles.py 4 Handler

A900-2b-2b (Kategorie 2, 3 Commits, mypy 23 -> 12):
  be60390  routes_changes.py 4 Handler
  5c9997b  routes_chat.py _json_error/chat_page/chat_api
  48320bc  routes_approvals.py 3 Handler

A900-2b-2c (Kategorie 2, 7 Commits, mypy 12 -> 2):
  c4db157  routes_settings.py
  c83b8d2  routes_inventory.py
  b362603  routes_audit.py
  b94a49c  routes_search.py
  908062d  routes_index.py
  88b9f0a  routes_alerts.py
  e0de381  filters.py

Ruff-I001-Fix (Kategorie 2 + 3, 2 Commits, ruff 2 -> 0):
  12d9a28  routes_settings.py Import-Block
  81a3607  change_service.py Import-Block

- B1: mypy-Aufraeumen (2026-09-30, HEAD 2de4a40).
  mypy 37 -> 0, ruff 0, Tests 1036 -> 1040.
  - B1d (404ba8e): Stubs (types-PyYAML,
    types-defusedxml) + fritzconnection-Override;
    Punkt 63 angelegt.
  - B1a (1e9adf0): apps/dashboard/_redirect.py neu
    (safe_redirect); app.py Session-Guard +
    request.endpoint-Guard + 3x safe_redirect;
    4 neue Tests.
  - B1c: entfaellt (durch B1d behoben).
  - B1b-1 (530fd88, 98429bc, a975723, c8f4569,
    9fd4d1d, 391f6ce): 6 Dashboard-Routen,
    Guards + safe_redirect.
  - B1b-2 (d93cc68, d77fd23, 2de4a40):
    orchestrator.py Punkt 60,
    chat.py Sequence[Any],
    loop.py no-redef (policy_approval_request_id).
  Punkt 60 erledigt. Punkt 63 erledigt.
  Punkt 64 entfaellt (B4 war Fehlalarm).

65. (offen, Kategorie 2, Dashboard) Extern-Kachel
    auf /. InventoryService.count_by_network
    liefert "Extern" bereits (T3), Kachel fehlt.
    Nach Punkt 55 vorgemerkt. Eigener kleiner
    Block.

66. (offen, Kategorie 3, Dashboard) Route /system
    mit vollem Diagramm (Verlauf mit Achsen,
    Zoom). Heute nur Sparklines auf / (T4).
    Eigener Block, eigenes Design.

67. (erledigt, Kategorie 3, Datenpfad) network_type
    pro Geraet aus IP ableiten.
    - Befund 2026-10-01: alle 7 Geraete in devices
      hatten network_type="Hauptnetz", obwohl
      2 im Gastnetz aktiv waren (192.168.189.2,
      192.168.189.4).
    - Ursache: tools/fritzbox_watcher.py nutzte
      get_fritz_network_type() (ein fester Wert
      fuer alle Events).
    - Auswirkung: Kachel "Gastnetz" immer 0,
      Kachel "Hauptnetz" zaehlte Gastnetz-Geraete
      mit.
    - Fix: core/config.py::resolve_network_type(ip)
      leitet aus GUEST_NETWORK_PREFIX (CIDR,
      Default 192.168.189.0/24) ab. Watcher ruft
      pro Host auf.
    - Kein "Extern" aus dieser Funktion
      (Detection-Kategorie, nicht Konfig).
    - DB-Backfill: dem naechsten Watcher-Lauf
      ueberlassen (upsert_seen ueberschreibt,
      weil neuer Wert nicht None).
    - LIMITATION (2026-10-01 abends): der Watcher
      erzeugt nur bei einem Diff (inaktiv -> aktiv
      oder neu) ein device_seen-Event. Solange ein
      Geraet ununterbrochen aktiv bleibt, laeuft
      upsert_seen nicht und der DB-Wert bleibt alt.
      Der Fix wirkt daher erst beim naechsten
      Diff-Event. Live-Verifikation offen
      (Handy kurz trennen, Watcher-Lauf 60s,
      danach DB pruefen).
      Siehe auch Punkt 68 (Watcher-Re-Presence).

67a. (offen, Kategorie 3, Watcher) entity_name-
     Ueberschreibung bei MAC-Fallback.
     - Befund 2026-10-01 abends: ein device_seen-
       Event fuer 82:E1:00:82:16:96 kam mit
       entity_name = "PC-82-E1-00-82-16-96"
       (MAC-Fallback der Fritz!Box) statt
       "S25-von-A".
     - upsert_seen ueberschreibt entity_name,
       weil der neue Wert nicht None ist.
     - Folge: der vom Nutzer vergebene Name geht
       in der DB verloren.
     - Fix-Vorschlag: Watcher soll MAC-Fallback-
       Namen ("PC-<MAC>") nicht als entity_name
       emittieren. Alternative: upsert_seen
       schreibt entity_name nur, wenn der neue
       Wert nicht dem Muster "PC-<MAC>" entspricht
       (fragil, weil Muster sich aendern kann).
       Besser: Watcher entscheidet, was ein echter
       Name ist.
     - Eigener Block, Reviewer-GO vor Code.

67b. (offen, Kategorie 3, Watcher/Datenpfad)
     empty-IP wird als "" gespeichert.
     - Befund 2026-10-01 abends: dasselbe
       device_seen-Event kam mit ip = ""
       (Fritz!Box liefert beim Zustandswechsel
       manchmal keine IP).
     - upsert_seen ueberschreibt last_ip nur,
       wenn der neue Wert nicht None ist.
       "" ist nicht None, also wird last_ip
       mit "" ueberschrieben.
     - Folge: in der DB steht last_ip="" statt
       der letzten gueltigen IP.
     - Fix-Vorschlag: Watcher emittiert ip=None,
       wenn die Fritz!Box keinen Wert liefert
       (statt ""). Dann greift upsert_seen
       korrekt.
     - Verwandt: 67 (IP-Ableitung), 68
       (Re-Presence).
     - Eigener Block, Reviewer-GO vor Code.

68. (offen, Kategorie 3, Watcher) Watcher-
    Re-Presence.
    - Der Fritz!Box-Watcher erzeugt heute nur bei
      Diff (inaktiv -> aktiv / neu) ein
      device_presence-Event.
    - Solange ein Geraet ununterbrochen aktiv
      bleibt, kein Event, kein upsert_seen,
      keine Aktualisierung von entity_name,
      network_type, last_ip in der DB.
    - Folge: Config-Aenderungen (wie
      resolve_network_type in Punkt 67) greifen
      erst, wenn der Diff irgendwann ausloest.
    - Fix-Vorschlag: zusaetzlich alle N Minuten
      (z. B. 60) ein device_presence fuer aktive
      Geraete emittieren. N als Konstante
      konfigurierbar.
    - Auswirkung: mehr Events in
      data/events-YYYY-MM-DD.jsonl (Aufwand
      pruefen), Orchestrator-Lauf alle 60s
      bereits vorhanden.
    - Verwandt: Punkt 49 (last_ip nur bei
      Diff-Events).
    - Eigener Block, Reviewer-GO vor Code.
    - Kein Bau heute (Doku).

Bewusst offen (kein Bau heute):
