# Context-Prompt für neue Chats

> Diesen Prompt kopieren, wenn ein neuer Chat begonnen wird.
> Stand: Phase 3.3 abgeschlossen.

---

## Prompt (ab hier kopieren)

Hallo. Ich arbeite am Projekt **Homelab Security AI** und
möchte daran weiterarbeiten. Bitte lies zuerst die folgenden
Informationen — danach bist du im Kontext.

### Wo das Projekt läuft

- Container: CT102 auf Proxmox, IP 192.168.178.117, Hostname security-ai
- Projektordner: /opt/security-ai
- GitHub: git@github.com:ghxstfocus/security-ai.git
  (privat, Branch: main, alles gepusht)
- Alter Container CT101 (192.168.178.116, /opt/homelab_security)
  läuft weiter, bleibt unangetastet.
- Debian, Python 3.11.2, pytest 7.2.1, PyYAML (apt python3-yaml),
  requests 2.28.1

### Architektur (Kurzform)

4-Ebenen-Modell:
- Ebene 5: Tools & Infrastruktur (Nmap, Scapy, Telegram, Proxmox)
- Ebene 4: Security AI (pro Netzwerk, lokal, autark)
- Ebene 3: Builder Harness (Tool Registry, Permissions 0-5, Audit)
- Ebene 2: Admin AI (optional, Cloud, MCP)
- Ebene 1: Human Admin (letzte Instanz)

Drei KI-Rollen: Human Admin, Security AI (lokal), Admin AI (Cloud).
Zwei Modi: A autark, B föderiert.

Grundprinzipien: Mensch behält Kontrolle, Defense in Depth,
Determinismus wo möglich, Autarkie, eine Quelle der Wahrheit,
Append-only Audit, Fail closed, Föderation statt Monolith.

### Was fertig ist

**Phase 1 — Harness + Docs:**
7 Docs + 7 Kernmodule: events, audit/writer, permissions/levels,
tool_registry/{tool,registry}, agent_loop/{loop,model}.
12 Tests (test_agent_loop.py).

**Phase 2 — Detection:**
core/detection/rule_base.py (Rule, RuleContext, RuleState),
core/detection/engine.py (DetectionEngine, RuleRunReport),
Regeln unknown_device + port_scan, detection/rules.yaml.

**Phase 2b — Inventory + Risk + Orchestrator + Audit:**
Inventory in SQLite (data/migrations/0002, devices, device_history,
whitelisted_devices), core/inventory/{device,repository,whitelist}.py.
Risk Engine (core/risk/{models,engine}.py + rules.yaml),
11 feste Pruefer, base + add-Modifier, Kategorien
EVENT/ANOMALY/SUSPICION/SECURITY_ALERT/CONFIRMED.
apps/security_ai/orchestrator.py mit process(event) und
Audit-Eintraegen (details.kind).

**Phase 3.1 — Policy Engine:**
harness/policy_engine/{policy,engine}.py,
policies/tools.yaml.
Decision ALLOWED/APPROVAL_REQUIRED/FORBIDDEN, strengste gewinnt.
Globale Pruefer (no_shell_chars, no_path_traversal,
no_null_bytes) laufen immer. Spezifische Pruefer nur via
conditions.

**Phase 3.2 — 5 Tools:**
tools/{nmap_scan,read_logs,get_devices,whitelist_check,
telegram_alert}.py. Alle über ToolRegistry registrierbar,
Argument-Validierung, source-Marker, fail closed.
nmap_scan und read_logs als Mock, get_devices/whitelist_check
lesen die echte DB, telegram_alert macht echtes HTTP.

**Phase 3.3 — Orchestrator + AgentLoop + Integration:**
apps/security_ai/planning.py (SecurityPlanModel, deterministisch),
apps/security_ai/config.yaml (loop_trigger_categories).
AgentLoop bekommt Policy-Check vor Argument-Validierung
(stateless, policy_context pro run()), Audit mit details.kind.
Orchestrator ruft AgentLoop fuer Alerts mit hoher Risk-Category.

**Tests: 179 grün** (Unit + Integration).
Alle Commits auf origin/main.

### Was als Nächstes kommt

- **Phase 3.4** — echter nmap-Aufruf (subprocess + Sandbox).
  Duenne Mock-Version in tools/nmap_scan.py ersetzen.
  Sandbox-Anforderungen: Timeout, kein Shell, stdout-Parsing.
- **Phase 4** — Guardrails + Approval-Flow, Change Requests.
- **Phase 5** — Admin AI (optional, Cloud, MCP).
- **Phase 6** — Physische Sicherheit (RFID, Zutritt).

### Format-Regeln

- Ein Codeblock pro Datei: `cat > ... << 'EOF' ... EOF`
- Danach: wc -l, py_compile, Test, git commit
- Keine Umlaute in Code-Bloecken (oe, ue, ae, ss)
- Kein sed auf Python-Code. Patches per Python-Skript
  (Path.read_text/replace/write_text)
- Bei langen Dateien zwei oder drei Bloecke
- Bei Fehlern: kurze Ursache, dann Fix

### Wo Details stehen

- docs/DESIGN_DECISIONS.md — Design-Entscheidungen,
  Audit-Nomenklatur, Test-Ebenen (LIES DAS bei Unklarheiten)
- docs/ARCHITECTURE.md — Architektur im Detail
- docs/SECURITY.md — Threat Model, Guardrails, Audit
- docs/PERMISSIONS.md — Berechtigungen (Level 0-5)
- docs/PROTOCOL.md — Foederationsprotokoll
- docs/DEPLOYMENT.md — Proxmox-Setup

### Aktuelle Phase

Phase 3.3 abgeschlossen (179 Tests grün).
Naechster Schritt: Phase 3.4 (echter nmap) oder Phase 4.

### Aufgabe jetzt

1. Bestätige in 3-4 Sätzen, dass du den Kontext verstanden hast.
2. Frag, ob wir direkt mit dem nächsten Schritt anfangen oder ob
   ich zuerst eine Datei posten soll.
3. Wenn ich "weiter" sage: Schreib mir die nächste Datei im oben
   beschriebenen Format.

---

## (Ende des Prompts)
