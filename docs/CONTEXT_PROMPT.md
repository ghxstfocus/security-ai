# Context-Prompt für neue Chats

> Diesen Prompt kopieren, wenn ein neuer Chat begonnen wird, um
> ohne Kontextverlust weiterzuarbeiten. Er ist für das LLM
> gedacht, nicht für den Menschen. Stand: Phase 2b abgeschlossen.

---

## Prompt (ab hier kopieren)

Hallo. Ich arbeite an einem Projekt namens **Homelab Security AI**
und möchte daran weiterarbeiten. Bitte lies zuerst die folgenden
Informationen — danach bist du im Kontext.

### Wo das Projekt läuft

- Container: CT102 auf Proxmox, IP 192.168.178.117, Hostname security-ai
- Projektordner: /opt/security-ai
- GitHub: git@github.com:ghxstfocus/security-ai.git
  (privat, Branch: main, alles gepusht)
- Alter Container CT101 (192.168.178.116, /opt/homelab_security)
  läuft weiterhin mit dem alten, produktiven System. Er bleibt
  unangetastet, bis das neue System reif ist.
- Debian, Python 3.11.2, pytest 7.2.1, PyYAML (apt install python3-yaml)

### Architektur (Kurzform)

**4-Ebenen-Modell:**

    Ebene 5:  TOOLS & INFRASTRUKTUR
              (Nmap, Scapy, Logs, Telegram, Proxmox, RFID, Türen)
    Ebene 4:  SECURITY AI  (pro Netzwerk/Gebäude, lokal, autark)
              Detection, Risk Engine, lokales LLM, Dashboard+Chat
    Ebene 3:  BUILDER HARNESS  (Kontrolle + Guardrails)
              Tool Registry, Permissions (0-5), Audit, Sandbox,
              Approval, Policy Engine, Versioning
    Ebene 2:  ADMIN AI  (optional, Cloud, Head of Operations)
              Change Requests, Korrelation, MCP-Kopplung
    Ebene 1:  HUMAN ADMIN  (letzte Instanz)
              Whitelist, Policies, Freigaben, Notfall-Stop

**Drei KI-Rollen:**
- Human Admin — letzte Instanz, pflegt Whitelist und Policies,
  gibt Change Requests frei
- Security AI — lokal/autark (Modus A), Detection + Risk, Dashboard
  mit Chat, bereitet Change Requests vor (führt sie nicht aus)
- Admin AI — Cloud, optional, korreliert über Netzwerke via MCP,
  kein Produktionszugriff, kein Whitelist-Schreibzugriff

**Zwei Betriebsmodi:**
- Modus A — Autark: pro Netzwerk eine Security AI, kein Cloud-Zwang
- Modus B — Föderiert: mehrere Security AIs + zentrale Admin AI

Modus A bleibt immer funktionsfähig. Admin AI ist optional.

**Grundprinzipien:**
1. Mensch behält 100% Kontrolle über kritische Entscheidungen
2. Defense in Depth
3. Determinismus wo möglich, KI nur wo nötig
4. Autarkie
5. Eine Quelle der Wahrheit
6. Append-only Audit
7. Fail closed
8. Keine Cloud-Abhängigkeit im Kern
9. Föderation statt Monolith
10. Physisch-digital vereint

**Skalierungspfad:**
Stufe 1 Netzwerk Homelab (heute) -> 2 Erweiterung (lokales LLM)
-> 3 Föderation (MCP) -> 4 Enterprise-Bridges -> 5 Physische
Sicherheit (RFID) -> 6 Ganzheitliche Korrelation.

### Projektstruktur (Überblick)

    apps/       security_ai (Orchestrator), dashboard, host_scanner, admin_ai
    core/       events, detection, risk, inventory
    harness/    agent_loop, tool_registry, permissions, audit
    tools/      Konkrete Tools (Phase 3)
    detection/  rules.yaml (Detection-Configs)
    data/       migrations/, inventory.db, audit-logs (via Konfig)
    policies/   YAML-Policies (Phase 3)
    changes/    Change Requests (Phase 3)
    docs/       README, PROJECT_VISION, PROTOCOL, ARCHITECTURE,
                SECURITY, PERMISSIONS, DEPLOYMENT, CONTEXT_PROMPT

### Was fertig ist

**Phase 1 — Harness + Docs:**
- 7 Docs (README, PROJECT_VISION, PROTOCOL, ARCHITECTURE,
  SECURITY, PERMISSIONS, DEPLOYMENT)
- core/events/event.py — Event-Modell (Event, Severity, EventType,
  new_event, new_event_id, with_data)
- harness/audit/writer.py — Append-only JSONL-Audit (AuditWriter,
  AuditEntry mit details-Feld, AuditWriteError)
- harness/permissions/levels.py — Permission-Level 0-5
- harness/tool_registry/{tool,registry}.py — Tool-Dataclass +
  Registry
- harness/agent_loop/{loop,model}.py — AgentLoop mit Policy/
  Permission/Audit/Budget

**Phase 2 — Detection:**
- core/detection/rule_base.py — Rule (ABC), RuleContext, RuleState
  (thread-sicherer Ringpuffer)
- core/detection/engine.py — DetectionEngine, RuleRunReport,
  load_rules_from_package, process(event, configs, history, now)
- core/detection/rules/unknown_device.py — Alarm bei Hauptnetz
  und known=False
- core/detection/rules/port_scan.py — stateful, drei Muster
  (port_scan, network_scan, brute_force) mit Cooldown
- detection/rules.yaml — Configs
- EventType.CONNECTION_ATTEMPT, EventType.SYN_PACKET ergänzt

**Phase 2b — Inventory + Risk + Orchestrator:**
- data/migrations/0002_inventory.sql — devices, device_history,
  whitelisted_devices (Whitelist eigene Tabelle, kein Feld in
  devices)
- core/inventory/device.py — Device (frozen), DeviceType
- core/inventory/repository.py — connect, apply_migrations,
  DeviceRepository (CRUD, upsert_seen, mark_offline,
  record_history)
- core/inventory/whitelist.py — WhitelistRepository (read-only +
  add/remove, History-Einträge whitelist_added/removed)
- core/risk/models.py — RiskAssessment, RiskCategory
  (EVENT/ANOMALY/SUSPICION/SECURITY_ALERT/CONFIRMED),
  RiskContext, clamp_score, score_to_category
- core/risk/engine.py — RiskEngine, 11 feste Prüfer (kein DSL,
  kein eval), base + add-Modifier, Pflicht-default-Block
- core/risk/rules.yaml — Regeln für unknown_device und port_scan
- apps/security_ai/orchestrator.py — SecurityAI, process(event)
  -> ProcessingResult in Reihenfolge Pre-Snapshot ->
  Inventory-Update -> Detection -> Alerts anreichern
  (first_seen) -> Risk -> Audit -> Snapshot-Hash

**Tests: 94 grün** (test_agent_loop 12, test_detection 8,
test_detection_engine 4, test_inventory 30, test_risk 28,
test_orchestrator 12). Letzter Commit auf origin/main.

### Was als Nächstes kommt (Phase 3 — Tools)

- tools/ füllen: Nmap, Scapy, Telegram, Fritzbox-Abfrage,
  Proxmox-API
- Tool-Klassen nutzen harness/tool_registry + permissions
- Policy Engine: policies/*.yaml
- Change Requests: changes/, Generator in Admin AI (Stufe 2)
- Audit-Integration in Tool-Aufrufe (tools nutzen
  harness/audit/writer.py)

Danach: Dashboard (apps/dashboard/), lokales LLM für
Erklärungen, Admin-AI-Anbindung via MCP.

### Format-Regeln

- Ein Codeblock pro Datei: `cat > ... << 'EOF' ... EOF`
- Danach: `wc -l`, `py_compile`, Test, Commit
- Keine Umlaute in Code-Blöcken (oe, ue, ae, ss)
- **Kein `sed` auf Python-Code** (hat mehrfach Dateien zerstört).
  Patches per Python-Skript mit Path.read_text/replace/write_text
- Bei langen Dateien lieber zwei oder drei Blöcke
- Bei Fehlern: kurze Ursache, dann Fix, keine langen Vorreden
- Nach jedem Schritt: git add + git commit mit klarer Nachricht

### Design-Entscheidungen (geklärt, gelten weiter)

1. Input und Output strikt getrennt: connection_attempt/syn_packet
   -> PORT_SCAN; device_presence/device_offline -> UNKNOWN_DEVICE.
2. State im RuleContext, nicht im Regel-Objekt (thread-sicher,
   resetbar).
3. DB nur im Orchestrator. Detection und Risk sind DB-frei und
   deterministisch.
4. Inventory-Update VOR Detection/Risk. Erstes Auftreten wird
   über first_seen=True im Alert signalisiert (Pre-Snapshot-
   Vergleich).
5. Append-only History: device_history.event_type frei,
   Konventionen device_seen, device_offline, whitelist_added,
   whitelist_removed.
6. Whitelist eigene Tabelle (whitelisted_devices), kein Feld in
   devices.
7. Risk Engine deterministisch, kein LLM. base + add-Modifier,
   auditierbar. LLM erklärt später nur.
8. Fail closed: unbekannter when-Name -> RiskRuleError, fehlender
   default-Block -> RiskRuleError, fehlende Predicate-Felder ->
   False.
9. Alert-Events erben event.timestamp (nicht now()), damit
   nachts/wochenende gegen Vorfall-Zeitpunkt prüfen.
   RiskAssessment.timestamp = Bewertungszeitpunkt.
10. Frischer Inventory-Snapshot pro process()-Call, NICHT pro
    Alert.
11. rules.yaml-Schema soll später multiply: und condition:
    aufnehmen können (noch nicht implementiert).
12. port_scan-Priorität: port_scan > network_scan > brute_force.
    brute_force kann parallel auftreten — später mehrere
    Output-Events pro Regel.

### Aufgabe jetzt

1. Bestätige in 3-4 Sätzen, dass du den Kontext verstanden hast.
2. Frag, ob wir direkt mit Phase 3 (Tools) anfangen oder ob ich
   zuerst eine Datei posten soll.
3. Wenn ich "weiter" sage: Schreib mir die nächste Datei im oben
   beschriebenen Format.

---

## (Ende des Prompts)
