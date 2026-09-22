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

Tests: 477 gruen (Unit + Integration, venv).

### Was als Naechstes kommt

- Phase 3.6.8+ — Web-Dashboard: einzelne Seiten mit echten
  Daten (Inventar, Alarme, Approvals, Changes, Chat, Users,
  Roles, Audit, Settings). Baut auf den Services
  (core/services) auf.
- Phase 3.7 (optional) — Host-Scanner / Netzwerk-Discovery
  (Proxmox-Watcher).
- Phase 3.5.5+ (optional) — Principal-Objekte, assign_role.
- Phase 5 — Admin AI (optional, Cloud, MCP). Setzt lokale KI
  voraus.

### Format-Regeln

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

### Aktuelle Phase

Phase 1-4 abgeschlossen. Phase 3.5 inkl. 3.5.5-3.5.9
abgeschlossen. Phase 3.6 (Web-Dashboard) in Arbeit:
3.6.1-3.6.7e fertig, Login + CSP + erste Seiten stehen.

Naechster Schritt: 3.6.8+ (einzelne Seiten mit Daten).

Tests: 477 gruen (venv, pytest 9.1.1).

### Aufgabe jetzt

Bestaetige in 3-4 Saetzen, dass du den Kontext verstanden hast.
Frag dann, ob wir direkt mit dem naechsten Schritt anfangen oder
ob ich zuerst eine Datei posten soll. Wenn ich "weiter" sage:
Schreib mir die naechste Datei im oben beschriebenen Format.

## (Ende des Prompts)
