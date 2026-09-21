# Context-Prompt für neue Chats

> Diesen Prompt kopieren, wenn ein neuer Chat begonnen wird, um
> ohne Kontextverlust weiterzuarbeiten. Er ist für das LLM
> gedacht, nicht für den Menschen. Er beschreibt, wo das Projekt
> steht, was fertig ist, was als Nächstes kommt und welche Regeln
> gelten.

---

## Prompt (ab hier kopieren)

Hallo. Ich arbeite an einem Projekt namens **Homelab Security AI**
und möchte daran weiterarbeiten. Bitte lies zuerst die folgenden
Informationen — danach bist du im Kontext.

### Wo das Projekt läuft

- Container: CT102 auf Proxmox, IP 192.168.178.117, Hostname security-ai
- Projektordner: /opt/security-ai
- GitHub: git@github.com:ghxstfocus/security-ai.git
  (privat, Branch: main)
- Alter Container CT101 (192.168.178.116, /opt/homelab_security)
  läuft weiterhin mit dem alten, produktiven System. Er bleibt
  unangetastet, bis das neue System reif ist.

### Projektstruktur (Überblick)

    apps/       security_ai, dashboard, host_scanner, admin_ai
    core/       events, detection, risk, inventory, protocol, reporting
    harness/    agent_loop, tool_registry, permissions, audit,
                guardrails, approval, sandbox, policy_engine, versioning
    tools/      Konkrete Tools (noch leer, kommen in Phase 3)
    detection/  YAML-Regeln (noch leer)
    data/       Migrationen, DB, Whitelist (noch leer)
    policies/   YAML-Policies (noch leer)
    changes/    Change Requests (noch leer)
    docs/       README, PROJECT_VISION, PROTOCOL, ARCHITECTURE,
                SECURITY, PERMISSIONS, DEPLOYMENT, CONTEXT_PROMPT

### Die Architektur (4-Ebenen-Modell)

    Ebene 5:  TOOLS & INFRASTRUKTUR
              (Nmap, Scapy, Logs, Telegram, Proxmox, RFID, Türen)

    Ebene 4:  SECURITY AI  (pro Netzwerk/Gebäude, lokal, autark)
              Detection, Risk Engine, lokales LLM, Dashboard+Chat

    Ebene 3:  BUILDER HARNESS  (Kontrolle + Guardrails)
              Tool Registry, Permissions (0-5), Audit, Sandbox,
              Approval, Policy Engine, Versioning

    Ebene 2:  ADMIN AI  (optional, Cloud, Head of Operations)
              Change Requests, Korrelation, MCP-Kopplung an
              externe LLMs (DeepSeek, Anthropic, OpenAI)

    Ebene 1:  HUMAN ADMIN  (letzte Instanz)
              Whitelist, Policies, Freigaben, Notfall-Stop

### Drei KI-Rollen

**Human Admin (der Mensch):**
- Letzte Instanz bei allen kritischen Entscheidungen
- Whitelist, Policies, Zutrittsberechtigungen pflegen
- Change Requests freigeben oder ablehnen

**Security AI (lokal, pro Netzwerk/Gebäude):**
- Läuft autark (Modus A), braucht die Admin AI nicht
- Detection, Risk Engine, lokales LLM für Erklärungen
- Dashboard mit Chat-Funktion für den Menschen
- Bereitet Change Requests vor (führt sie nicht aus)

**Admin AI (Cloud, optional):**
- Eigene Instanz, an die Security AIs angekoppelt über MCP
- Korreliert Events über mehrere Netzwerke/Gebäude
- Generiert Change Requests, schreibt Code, schlägt Tests vor
- Spricht über MCP mit externen LLMs (Anthropic, OpenAI)
- Kein direkter Produktionszugriff, kein Whitelist-Schreibzugriff

### Zwei Betriebsmodi

**Modus A — Autark:** Eine Security AI pro Netzwerk, lokales LLM,
keine Cloud. Mensch entscheidet alles.

**Modus B — Föderiert:** Mehrere Security AIs + zentrale Admin AI
über MCP. Mensch entscheidet weiterhin alles.

Wichtig: Modus A bleibt immer funktionsfähig. Die Admin AI ist
optional.

### Grundprinzipien

1. Mensch behält 100% Kontrolle über kritische Entscheidungen
2. Defense in Depth
3. Determinismus wo möglich, KI nur wo nötig
4. Autarkie (lokale Security AI funktioniert ohne Admin AI)
5. Eine Quelle der Wahrheit (Policies, Whitelist, Events)
6. Append-only Audit
7. Fail closed
8. Keine Cloud-Abhängigkeit im Kern
9. Föderation statt Monolith
10. Physisch-digital vereint (Zutritt + Netzwerk korreliert)

### Skalierungspfad (6 Stufen)

- Stufe 1: Netzwerk Homelab (heute)
- Stufe 2: Erweiterung (Change-Request-Generator, lokales LLM)
- Stufe 3: Föderation (mehrere Netzwerke, MCP)
- Stufe 4: Enterprise-Bridges (externe LLMs)
- Stufe 5: Physische Sicherheit (RFID, Zutritt, Räume)
- Stufe 6: Ganzheitliche Korrelation (physisch + digital)

### Was bereits fertig ist (Phase 1)

Docs (7):
- README.md
- PROJECT_VISION.md (erweitert: 3 KI-Rollen, 6 Stufen,
  physische Sicherheit, ethische Leitplanken)
- docs/PROTOCOL.md (MCP-Föderationsprotokoll)
- docs/ARCHITECTURE.md (4-Ebenen-Modell im Detail)
- docs/SECURITY.md (Threat Model, Guardrails, Audit)
- docs/PERMISSIONS.md (Level 0-5)
- docs/DEPLOYMENT.md (Proxmox-Setup)

Code (7 Kernmodule):
- core/events/event.py — Event-Modell
  (Event, Severity, EventType, new_event, new_event_id)
- harness/audit/writer.py — Append-only JSONL-Audit
  (AuditWriter, AuditEntry, AuditWriteError)
- harness/permissions/levels.py — Permission-Level 0-5
  (Level, check_level, ForbiddenActionError)
- harness/tool_registry/tool.py — Tool-Dataclass + Validierung
  (Tool, ToolValidationError, ToolArgumentError)
- harness/tool_registry/registry.py — ToolRegistry
  (register, get, list, list_by_level)
- harness/agent_loop/loop.py — AgentLoop mit
  Policy/Permission/Audit/Budget
  (AgentLoop, LoopBudget, LoopResult, Plan, PlanStep)
- harness/agent_loop/model.py — BaseModel, DummyModel,
  RuleModel, CallableModel

Tests (12, alle grün):
- tests/unit/test_agent_loop.py

Git-Historie: ca. 15+ Commits

### Was als Nächstes kommt (Phase 2)

Detection Engine:
- core/detection/rule_base.py — Interface für Regeln
- core/detection/engine.py — Regel-Engine, lädt YAML
- core/detection/rules/unknown_device.py — Erste Regel
- core/detection/rules/port_scan.py — Zweite Regel
- detection/rules.yaml — Deklarative Regeln
- tests/unit/test_detection.py — Tests für die Regeln

Danach Phase 2b: Risk Engine (core/risk/),
Inventory (core/inventory/).

### Format-Präferenzen des Nutzers

- Ein Codeblock pro Datei: `cat > ... << 'EOF' ... EOF`
- Danach: `wc -l`, `py_compile`, Test, Commit
- Erklärungen außerhalb des Codeblocks, knapp halten
- **Keine Umlaute in Code-Blöcken** (Locale-Probleme beim
  Kopieren — `oe`, `ue`, `ae`, `ss` stattdessen)
- **Kein `sed` auf Python-Code** (hat mehrfach Dateien zerstört)
- Bei langen Dateien lieber zwei oder drei Blöcke
- Nach jedem Schreiben: `py_compile` + kurzer Test
- Nach jedem Schritt: `git add` + `git commit` mit klarer
  Nachricht
- Bei Fehlern: keine langen Vorreden, direkt zur Lösung

### Aufgabe jetzt

1. Bestätige in 3-4 Sätzen, dass du den Kontext verstanden hast.
2. Frag, ob wir direkt mit Phase 2 anfangen oder ob ich zuerst
   eine Datei posten soll.
3. Wenn ich "weiter" sage: Schreib mir die nächste Datei im
   oben beschriebenen Format.

---

## (Ende des Prompts)
