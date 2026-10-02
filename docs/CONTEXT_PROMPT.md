## Prompt (ab hier kopieren)

Hallo. Ich arbeite am Projekt Homelab Security AI und moechte
daran weiterarbeiten. Bitte lies diesen Prompt komplett — danach
bist du im Kontext.

### Wo das Projekt laeuft

- Container: CT102 auf Proxmox, IP 192.168.178.117,
  Hostname security-ai
- Projektordner: /opt/security-ai
- GitHub: git@github.com:ghxstfocus/security-ai.git
  (privat, Branch main, alles gepusht)
- Alter Container CT101 (192.168.178.116) ruht, bleibt unberuehrt
- Debian 12, Python 3.11, pytest 9.1.1 (venv)
- CT102: 16 GB Disk, 12 GB RAM, 4 Kerne
- Ollama laeuft lokal (llama3.2:3b Default, qwen2.5:7b Large)

### Architektur (Kurzform)

4-Ebenen-Modell:

- Ebene 5: Tools & Infrastruktur (nmap, Scapy, Telegram, Proxmox)
- Ebene 4: Security AI (pro Netzwerk, lokal, autark)
- Ebene 3: Builder Harness (Tool Registry, Permissions 0-5, Audit)
- Ebene 2: Admin AI (optional, Cloud, MCP)
- Ebene 1: Human Admin (letzte Instanz)

Drei KI-Rollen: Human Admin, Security AI (lokal), Admin AI (Cloud).
Zwei Modi: A autark, B foederiert.

Service-Schicht (Phase 3.5):
UI (Web/CLI/Telegram) -> Services (core/services) -> Repos (core/).

Frage-Klassifikation (Phase 3.5.8):
- fact           -> deterministische Antwort, kein LLM
- concept        -> LLM (3B), kein Kontext-Zwang
- interpretation -> LLM mit Kontext (7B via Auto-Switch)

Grundprinzipien: Mensch behaelt Kontrolle, Defense in Depth,
Determinismus wo moeglich, Autarkie, eine Quelle der Wahrheit,
Append-only Audit, Fail closed, Foederation statt Monolith.

### Was fertig ist

- Phase 1 — Harness + Docs (7 Module, events, audit,
  permissions, tool_registry, agent_loop)
- Phase 2 — Detection (Rule, Engine, unknown_device, port_scan)
- Phase 2b — Inventory + Risk + Orchestrator + Audit
  (SQLite, core/inventory, core/risk, apps/security_ai)
- Phase 3.1 — Policy Engine (harness/policy_engine, policies/)
- Phase 3.2 — 5 Tools (nmap_scan, read_logs, get_devices,
  whitelist_check, telegram_alert)
- Phase 3.3 — Orchestrator + AgentLoop + Integration
  (apps/security_ai/planning.py, config.yaml)
- Phase 3.4 — Echter nmap-Aufruf (subprocess + Sandbox,
  Timeout, Whitelists, XML)
- Phase 4 — Approval + Change Requests (Migrationen 0003+0004,
  core/approval, core/changes, approvals_cli, changes_cli,
  _notify_approval, ChangeApplier-Stub)
- Phase 3.5 — Lokale KI: core/config, harness/llm (Ollama),
  harness/context (ContextBundle, ContextBuilder, Redaction),
  core/access (RBAC), core/services (AccessService),
  apps/security_ai/chat.py (ChatService), scripts/init_db.py,
  scripts/chat_cli.py
- Phase 3.5.5 — Service-Refactor: Repo-Injection im
  AccessChecker + from_conn; DI in ChatService/AccessService
- Phase 3.5.6 — Kontext-Anschluss: core/reporting/audit_reader
  (risk_assessments aus JSONL), core/reporting/inventory_snapshot,
  chat_cli laedt Kontext
- Phase 3.5.7 — Auto-Switch zu qwen2.5:7b; no_context-Pfad;
  Prompt-Verbesserungen
- Phase 3.5.7a — Modellabhaengige Timeouts (3B: 30s, 7B: 180s),
  --no-auto-large
- Phase 3.5.7b — on_model_selected-Callback (Warnung vor LLM)
- Phase 3.5.8 — Frage-Klassifikation (fact/concept/interpretation),
  Fact-Pfad deterministisch, kein LLM bei Fakten
- Phase 3.5.9 — Sanity-Check (Denial + Underreporting) + Retry
  mit 7B; Auto-Switch bei kritischen Assessments ist PFLICHT
- Phase 3.6.1 — Session-Modell + SessionRepository +
  LoginAttemptRepository (Migration 0006)
- Phase 3.6.2 — get_secret_key + ConfigError (fail closed)
- Phase 3.6.3 — AccessService.set_password
  (RBAC + Session-Invalidierung)
- Phase 3.6.4 — AuditReaderService (RBAC, nur Lesen)
- Phase 3.6.5 — Flask-App-Factory + RBAC-Middleware
  (before_request, Sicherheitsnetz, Errorhandler)
- Phase 3.6.6 — Login + Logout + CSRF + Rate-Limit
  + Audit (csrf.py, auth.py)
- Phase 3.6.7a — Static (CSS, JS, SVG-Favicon)
- Phase 3.6.7b — base.html + Partials + CSP-Header
  (strict, kein unsafe-inline)
- Phase 3.6.7c — login.html als Template
- Phase 3.6.7d — index.html + Route / (device.read)
- Phase 3.6.7e — CSP-Header-Test (alle Direktiven)
- Phase 3.6.8 — Web-Dashboard-Seiten mit echten Daten
  (a-i, komplett):
    a Inventar (/inventory, device.read)        2d4b437
    b Alarme (/alerts, alert.view)              6ae8bd5
      Fix: AuditReaderService.base_dir          8d43034
    c Approvals (/approvals, approval.view +
      approval.decide, CSRF, Variante A)        25d9614
    d Changes (/changes, change.view +
      change.create; errors.py mit
      ServiceError/OperationError)              29535ce
    e Chat (/chat + /api/chat, chat.ask,
      RateLimitService, CSRF-Header,
      _inject_csrf)                             148b434
    f Benutzer (/users, principal.manage,
      principal_to_view, MIN_PASSWORD_LEN=12,
      list_roles mit principal.manage)          1f16127
    g Rollen (/roles, role.manage, role_to_view,
      permission_to_view, assign/revoke,
      self-critical Warnung)                    9c3accb
    h Audit (/audit, audit.read, Tag-Filter,
      details formatiert, kein read_all)        fbfafc6
    i Einstellungen (/settings, role.manage,
      read-only)                                14cccd5
  Doku-Abschluss 3.6.8                           3beab99

### Was als Naechstes kommt

- Phase 3.6.10 — Responsive-Feinschliff (Kategorie 1,
  CSS-only: .table auf <700px, .topbar, .card,
  .form-input). Keine Template-Aenderung.
- Phase 3.6.11 — Hamburger-Navigation (Kategorie 3:
  Button in topbar.html, Toggle in static/js/nav.js,
  extern, addEventListener, kein onclick=, kein
  Inline-<script>, keine style="...", CSP-konform).
- Phase 3.7 (optional) — Host-Scanner / Netzwerk-Discovery
  (Proxmox-Watcher).
- Phase 3.5.5+ (optional) — Principal-Objekte, assign_role.
- Phase 5 — Admin AI (optional, Cloud, MCP). Setzt lokale KI
  voraus.

### Format-Regeln

Der generische Prozess (Fakten-Check-Takt, Kategorien,
Selbst-Review, Patch-Template, Verifikations-Reihenfolge,
Anti-Patterns) steht in docs/WORKFLOW.md — projektunabhaengig,
in jedes neue Projekt kopierbar. Die folgenden Format-Regeln
sind projektspezifische Ergaenzungen dazu.

- **Vor jedem Patch einer bestehenden Datei: erst `cat`en.**
  Anker-Strings muessen aus dem echten Inhalt stammen, nicht
  aus dem Gedaechtnis. Sonst gehen Inhalte verloren (Beispiel:
  `.env.example`, `PROJECT_VISION.md` Stufe 2.5).

- Lies IMMER erst den Code, bevor du baust. Der Chat plant die
  Richtung, der Code ist die Wahrheit.
- Nie `cat > datei << EOF` bei bestehenden Config- oder
  Doku-Dateien. Erst lesen, dann per Python-Skript ergaenzen
  (Path.read_text / str.replace / Path.write_text).
  `cat >` nur bei neuen Dateien.
- Ein `&&`-Block pro logischer Einheit. Bei Fehlschlag bricht
  die Kette vor `git commit` ab; der naechste Block zieht nur
  die unfertige Datei nach.
- **Fakten-Check-Takt (verbindlich fuer Bau-Chat und
  Reviewer):** Pro Nachricht genau EIN Ausfuehrungsblock.
  Der naechste Block kommt erst, nachdem der Nutzer die
  Ausgabe des vorherigen gepastet hat. Kein Vorab-Stapeln
  mehrerer Bloecke. Mehrere Fakten sequenziell klaeren.
  Grund: Scroll-Chaos beim Nutzer, doppelte Befehle,
  schwer nachvollziehbare Reihenfolge.
- Keine Umlaute in Code-Bloecken (oe, ue, ae, ss).
- Kein sed auf Python-Code. Patches per Python-Skript.
- Bei Auflagen mit Jinja-Syntax oder API:
  vorher pruefen (Doku, inspect.signature),
  nicht aus dem Gedaechtnis.
- Nach jedem Schritt: wc -l, py_compile, pytest -q, git commit.
- **Immer `/opt/security-ai/.venv/bin/python3` verwenden**,
  nicht `/usr/bin/python3`. Grund: System-Python hat nicht
  die pyproject-Dependencies (Flask, PyYAML, requests,
  psutil).
- Tests immer aus `/opt/security-ai` ausfuehren.
  `detection/rules.yaml`, `policies/tools.yaml`,
  `core/risk/rules.yaml` werden relativ zum CWD geladen.
- `scripts/*` sind Werkzeuge, keine Bibliothek.
  Nur aus `/opt/security-ai` importierbar.

### Wo Details stehen

- PROJECT_VISION.md (Root) — Vision, Skalierungspfad
- README.md (Root) — Kurzueberblick
- docs/ARCHITECTURE.md — Architektur im Detail
- docs/SECURITY.md — Threat Model, Guardrails, Audit
- docs/PERMISSIONS.md — Berechtigungen Level 0-5
- docs/PROTOCOL.md — Foederationsprotokoll, Statusmodell
- docs/DEPLOYMENT.md — Setup, nmap, Ollama, Tuning
- docs/DESIGN_DECISIONS.md — Design-Entscheidungen,
  Audit-Nomenklatur, Test-Ebenen
- docs/PHASES.md — Phasenuebersicht mit Status
- docs/WERKZEUGE.md — Skripte und CLIs (init_db, chat_cli,
  approvals_cli, changes_cli)
- docs/WEB_SECURITY_CHECKLIST.md — verbindliche
  Security-Checkliste fuer Phase 3.6 (Web-Dashboard)
- docs/SECURITY_REVIEW_LOG.md — Sicherheits-
  Entscheidungen nach Thema + offene Punkte 1-11
  (Stand Punkt 55 abgeschlossen, mypy 0)
- docs/INCONSISTENCIES_FOUND.md — Ausgelagerte
  Inkonsistenzen (heute keine)
- docs/WORKFLOW.md — generischer Prozess (Rollen,
  Fakten-Check-Takt, Kategorien, Selbst-Review,
  Patch-Template, Verifikation, Anti-Patterns).
  Projektunabhaengig, in andere Projekte kopierbar.
- docs/REVIEWER_HANDOFF.md — Handoff-Prompt fuer
  den externen Reviewer-Chat (Kategorie 3)

### Projekt-Konventionen (projektspezifische Hard-Rules)

Diese Konventionen sind zusaetzlich verbindlich. Die
generischen Hard-Rules stehen in
WORKFLOW.md Abschnitt "Hard-Rules (VERBINDLICH)".

1. Python-Interpreter: `/opt/security-ai/.venv/bin/python3`
   (nicht `/usr/bin/python3`; System-Python hat die
   pyproject-Dependencies nicht).
2. CWD fuer Tests: `/opt/security-ai`
   (`detection/rules.yaml`, `policies/tools.yaml`,
   `core/risk/rules.yaml` werden relativ zum CWD
   geladen).
3. Git-Remote/Branch: `origin/main`.
4. Testzahl-Quelle:
   `/opt/security-ai/.venv/bin/python3 -m pytest
   --collect-only -q | tail -1`.
5. Doku-Dateien in diesem Projekt:
   `docs/PHASES.md`, `docs/CONTEXT_PROMPT.md`,
   `docs/SECURITY_REVIEW_LOG.md`,
   `docs/DESIGN_DECISIONS.md`.
6. Reviewer-Pflicht: Kategorie 3 laut
   WORKFLOW.md Abschnitt "Kategorien".

### Aktuelle Phase

Phase 1-4 abgeschlossen. Phase 3.5 inkl. 3.5.5-3.5.9
abgeschlossen. Phase 3.6 (Web-Dashboard):
3.6.1-3.6.7e fertig.
Phase 3.6.8 (alle Dashboard-Seiten) KOMPLETT:
a-i.
Phase 3.6.10 bis 3.6.17 fertig (inkl. 16a/16b
gunicorn, Punkt 9 Rate-Limit, Punkt 19 Pro-Tabelle).
Zusaetzlich fertig: Punkt 28 (Chat-Kontext),
Punkt 29 (Wert-Synonyme), Punkt 30 (Links im Chat),
3.6.18a (category durchsuchbar), UI-Feinschliff
(SVG, Spalten, Sidebar, Suche, Topbar-Dropdown),
Diagnose 2026-09-27 (ruff/mypy eingerichtet).
HEAD 33b5985, Working Tree sauber.

Core-Status: Core (Stufe 1-3.6.18) abgeschlossen.
Fritz!Box-Watcher (Phase 3.8a) und Event-Reader
(Phase 3.8b) laufen als systemd-Timer.
Der Alarm-Pfad nutzt notify_ntfy (Punkt 81).

Bewusst offen (kein Bau heute):
- Punkt 76: Telegram-Kanal konfigurieren
  (Kategorie 1, Betriebsakt).
- Punkt 80: Alarme-Seite Filter + Pagination
  (Kategorie 3, UI).
- Punkt 83: CONTEXT_PROMPT-Sanierung
  (Kategorie 1, Doku).
- Punkt 84: Heredoc-Zerhackung
  (Kategorie 1, Doku).
- Punkte 87-101: Ausblick-Themen
  (Wortlaut offen).
- Lint/Typen-Reste:
  - ruff 0 (A900 + B1 abgeschlossen).
  - mypy 0 (A900 + B1 abgeschlossen).
  - Echte Typfehler: 0.

Offene Punkte 1-41 in docs/SECURITY_REVIEW_LOG.md.
Chronologie bis 33b5985 dokumentiert (sortiert nach
Commit-Zeit).
DESIGN_DECISIONS: §11 (Kontext, Wert-Synonyme,
Suchfelder), §14 (Frage-Klassifikation, Anzeige-Labels,
since_hours), §16 (ProxyFix, Links im Chat, nav_links,
JS-Ausnahme, server_name, default_server).

Stand: 2026-10-02 | HEAD: 33b5985 |
Tests: 1192 gruen (venv, pytest 9.1.1).
Drei Blickwinkel auf dieselbe Architektur:
- Technische Schichten 5-1 (docs/ARCHITECTURE.md).
- Rollen im Betrieb (PROJECT_VISION.md, README.md).
- Test-Ebenen 1-5 (docs/DESIGN_DECISIONS.md).
Heute abgeschlossen: Punkt 81 (Alarm-Kanal auf
notify_ntfy, live verifiziert), Punkt 82 (Docstring
5->6 Tools), Doku-Block drei Blickwinkel (README,
PROJECT_VISION 2.0, PHASES, dieser Prompt), README-
Neuschrieb (Haltung + Rollensicht), PROJECT_VISION-
Rollensicht (Commit 1 + 2).
Offen: Punkt 76 (Telegram), 80 (Filter + Pagination),
83 (dieser Prompt), 84 (Heredoc), 87-101 (Ausblick).
Quelle der Wahrheit ist `pytest --collect-only -q`.

### Aufgabe jetzt

Bestaetige in 3-4 Saetzen, dass du den Kontext verstanden hast.
Frag dann, ob wir direkt mit dem naechsten Schritt anfangen oder
ob ich zuerst eine Datei posten soll. Wenn ich "weiter" sage:
Schreib mir die naechste Datei im oben beschriebenen Format.

## (Ende des Prompts)
