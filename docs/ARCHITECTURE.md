# Architektur — Homelab Security AI

> Technische Detailbeschreibung der 4-Ebenen-Architektur,
> ihrer Komponenten, Datenflüsse und Verantwortlichkeiten.

## 1. Überblick

Das System ist in vier strikt getrennte Ebenen aufgeteilt.
Jede Ebene hat eine klar definierte Verantwortung.

    Ebene 5:  TOOLS & INFRASTRUKTUR
    Ebene 4:  SECURITY AI          (pro Netzwerk)
    Ebene 3:  BUILDER HARNESS      (Kontrolle + Guardrails)
    Ebene 2:  ADMIN AI             (Koordination, Vorschläge)
    Ebene 1:  HUMAN ADMIN          (Entscheidungen, Freigaben)

Datenfluss aufwärts: Events, Beobachtungen.
Datenfluss abwärts: Change Requests, Entscheidungen.

## 2. Die Ebenen im Detail

### Ebene 5 — Tools & Infrastruktur

Die konkreten Werkzeuge und Systeme:

- Nmap — Netzwerk-Scanning (nur autorisierte Hosts)
- Scapy — Paket-Sniffing (Host-Scanner)
- Fritz!Box API — Geräte-Inventar
- Proxmox API — Infrastruktur-Status
- Docker API — Container-Status
- SQLite — Datenhaltung
- Telegram — Alarmierung
- Linux-Logs — Systemereignisse

Regeln:

- Jedes Tool wird nur über die Tool Registry aufgerufen.
- Kein direkter Shell-Zugriff durch das Modell.
- Capabilities werden im Security-Container entzogen.

### Ebene 4 — Core (Security AI)

Läuft pro Netzwerk in einem eigenen Container.

Aufgaben:

- Empfängt Events von Watchern (Netzwerk, Docker, Proxmox, UEBA)
- Wendet deterministische Detection-Regeln an
- Berechnet Risk-Scores
- Sendet Alarme (Telegram) bei Sicherheitsvorfällen
- Loggt alles in die Datenbank

Was sie NICHT tut:

- Keine Änderungen am System
- Kein direkter Shell-Zugriff
- Kein Umgehen des Harness

Komponenten:

- apps/security_ai/ — Hauptprozess
- core/detection/ — Regel-Engine
- core/risk/ — Risk Engine
- core/inventory/ — Geräte, Whitelist
- core/events/ — Event-Modell

### Lokale KI (Phase 3.5) — entfernt (Phase 16)

Dieser Abschnitt beschreibt, wie der lokale
Ollama-Chat funktionierte. Er ist mit dem
Ollama-Rueckbau (Phase 16) obsolet. Die
Cloud-Provider uebernehmen die Intelligenz-
schicht (siehe docs/ADMIN_AI_SCOPE.md).

Die Security AI wird zur echten KI. Ein lokales LLM erklaert,
entscheidet aber nicht.

LLM:

- Ollama als Laufzeitumgebung, kein Cloud-Zugriff.
- Default-Modell: qwen2.5:7b.
- Kleinere Alternative: llama3.2:3b (weniger RAM).

Rolle: Erklaeren, nicht Entscheiden.

- Detection, Risk und Policy bleiben deterministisch.
- LLM-Output fliesst NICHT in Policy-Entscheidungen,
  Risk-Scores, Approval-Entscheidungen oder
  Change-Freigaben.
- Das LLM liest Ergebnisse und formuliert Klartext fuer
  den Human Admin.

Kontext-Bauer (spaeter harness/context/):

- Baut vor jedem LLM-Aufruf einen strukturierten Kontext
  aus Events, DB-Historie, Log-Ausschnitten und
  Inventory-Status.
- Filtert Rohdaten, damit das LLM keine Freitext-Eingaben
  aus unbekannten Quellen sieht (Prompt-Injection-Schutz).
- Selbst auditierbar.

Chat-Interface:

- Ort: apps/dashboard/.
- Human Admin fragt, LLM erklaert.
- Kein Tool-Aufruf aus dem Chat.
- Antworten sind Vorschlaege, keine Aktionen.

Details: siehe docs/DESIGN_DECISIONS.md, Abschnitt 8.

### Ebene 3 — Builder Harness

Die kontrollierte Ausführungsumgebung. Sie ist die einzige
Schicht, die tatsächlich Tools aufruft.

Aufgaben:

- Tool Registry: Welche Tools existieren? Welche Parameter?
- Permissions: Welches Level hat ein Tool? (0-5)
- Guardrails: Welche Aktionen sind verboten?
- Sandbox: Isolation pro Tool
- Policy Engine: Regeln für Aktionen
- Approval: Human-in-the-Loop
- Audit: Append-only-Log
- Versioning: Change Management

Regeln:

- Kein Tool-Aufruf ohne Harness.
- Guardrails sind Code, nicht Prompt.
- Fail closed: Wenn ein Guardrail nicht prüfen kann, blockiert er.

### Ebene 2 — Admin AI

Pflicht, wenn das System als Sicherheitssystem
genutzt wird. Ohne Admin AI bleibt der Core ein
deterministischer Detektor und Regelvollstrecker.
Läuft zentral in der Cloud der Firma.

Cloud-Provider sind austauschbar: Azure (deutscher
Standard), Anthropic, OpenAI, DeepSeek, Copilot.

Details: siehe docs/ADMIN_AI_SCOPE.md.

Aufgaben:

- Korreliert Events aus mehreren Netzwerken
- Erkennt Muster über Netzwerke hinweg
- Generiert Change Requests
- Prüft Code, Tests, Policies
- Schlägt Verbesserungen vor

Was sie NICHT tut:

- Kein direkter Produktionszugriff
- Kein Schreibzugriff auf Policies oder Whitelist
- Kein autonomer Deploy

Zugriff:

- Liest Code (read-only)
- Schreibt Change Requests in changes/
- Kommuniziert über das Föderationsprotokoll

### Ebene 1 — Human Admin

Der Mensch. Letzte Instanz bei allen kritischen Entscheidungen.

Aufgaben:

- Whitelist pflegen
- Change Requests freigeben oder ablehnen
- Policies anpassen
- Notfall-Stop

Regeln:

- Jede Aktion mit Risiko-Level >= 2 braucht Freigabe.
- Whitelist ist Mensch-only.
- Kein LLM-Schreibzugriff auf Guardrails.

## 3. Komponenten im Detail

### 3.1 core/events — Event-Modell

Ein einheitliches Schema für alle Sicherheitsereignisse.

    @dataclass
    class Event:
        event_id: str           # EVT-YYYY-MM-DD-NNNNN
        timestamp: datetime
        source: str             # "fritzbox", "docker", "scapy", ...
        event_type: str         # "unknown_device", "port_scan", ...
        severity: Severity      # INFO, WARNING, CRITICAL
        data: dict              # typ-spezifische Daten
        network_id: str         # z.B. "homelab-ct101"

Events sind unveränderlich. Sie werden geloggt und niemals
überschrieben.

### 3.2 core/detection — Detection Engine

Wendet deterministische Regeln auf Events an. Kein LLM.

Regeln sind in detection/rules.yaml definiert:

    - id: unknown_main_device
      event_type: device_presence
      conditions:
        - network_type == "Hauptnetz"
        - is_known == false
      severity: WARNING

Die Engine lädt die Regeln, prüft sie gegen eingehende Events und
erzeugt daraus Detections.

### 3.3 core/risk — Risk Engine

Bewertet Detections und ordnet sie ein:

| Kategorie          | Bedeutung                              |
|--------------------|----------------------------------------|
| EVENT              | Normale Aktivität                      |
| ANOMALY            | Ungewöhnlich, nicht zwingend bösartig  |
| SUSPICION          | Verdacht                               |
| SECURITY_ALERT     | Sicherheitsrelevant                    |
| CONFIRMED CONDITION| Bestätigter Vorfall                    |

Berechnet einen Confidence-Score aus:

- Wie viele unabhängige Quellen bestätigen?
- Wie nah am Whitelist-Verhalten?
- Wie oft in den letzten 30 Tagen gesehen?

Wichtig: Die Risk Engine ist der einzige Ort, an dem das
LLM mitreden darf — bei der Erklärung. Nicht bei der Bewertung.

### 3.4 core/inventory — Inventar & Whitelist

Einzige Quelle der Wahrheit für:

- Geräte-Inventar — welche Geräte gibt es?
- Whitelist — welche Geräte sind erlaubt?
- Historie — was war wann online?

Regeln:

- Whitelist wird nur vom Menschen gepflegt.
- Kein Auto-Add, kein LLM-Schreibzugriff.
- Jede Änderung wird auditiert.

### 3.5 harness/agent_loop — Agent-Ablauf

Der sequenzielle Ablauf für jede Aktion:

    INPUT
      -> CONTEXT          (Was ist passiert?)
      -> MODEL            (LLM wird befragt)
      -> PLAN             (Was soll getan werden?)
      -> POLICY CHECK     (Erlaubt?)
      -> TOOL SELECTION   (Welches Tool?)
      -> PERMISSION CHECK (Level ok?)
      -> EXECUTION        (Tool ausführen)
      -> RESULT VALIDATION(Ergebnis prüfen)
      -> MODEL ANALYSIS   (Ergebnis erklären)
      -> DECISION         (Was tun?)
      -> ACTION/ALERT/APPROVAL
      -> AUDIT            (Loggen)

Begrenzt durch:

- max_iterations
- max_runtime
- max_tool_calls
- Ressourcen-Limits

Fuer Level 0-1 read-only entfaellt der Policy-Check.
Der ToolRunService ruft direkt auf (Werkbank-Registry).
Siehe WEB_SECURITY_CHECKLIST §N-Ausnahme Werkbank.

### 3.6 harness/tool_registry — Tool Registry

Zentrale Verwaltung aller Tools.

    @dataclass
    class Tool:
        name: str
        level: Level             # 0-5
        sandbox_profile: str
        func: Callable
        allowed_args: set[str]
        description: str
        version: str

Regel: Kein nicht registriertes Tool kann ausgeführt werden.

Die Werkbank-Registry (tools/workbench_registry.py)
ist eine zweite Registry, unabhaengig vom AgentLoop. Sie
enthaelt nur Level 0-1 read-only Tools und wird
ausschliesslich vom ToolRunService genutzt.

### 3.7 harness/permissions — Permission System

Jedes Tool hat ein Level:

| Level | Beschreibung          | Beispiele                          |
|-------|-----------------------|------------------------------------|
| 0     | READ / LOW RISK       | read_logs, get_devices             |
| 1     | SECURITY ACTION       | nmap (authorized), telegram_alert  |
| 2-3   | HIGH RISK ACTION      | firewall change, block device      |
| 4-5   | APPROVAL / FORBIDDEN  | modify guardrails, modify policies |

Regel: Was nicht explizit erlaubt ist, ist verboten.

### 3.8 harness/guardrails — Guardrails

**Status:** geplant (Phase 4). Teilweise abgedeckt in
`harness/policy_engine` (globale Pruefer `no_shell_chars`,
`no_path_traversal`, `no_null_bytes`; spezifische Pruefer
`target_in_scope`, `authorized_target`, `read_only_path`).

Nicht überschreibbare Schutzmechanismen. Code, nicht Prompt.

- scope_guard.py — Nur autorisierte Netzbereiche
- self_mod_guard.py — Kein Ändern eigener Policies
- audit_guard.py — Audit nicht deaktivierbar
- prompt_injection_guard.py — Erkennt und blockt Injection

Regel: Fail closed. Wenn ein Guardrail nicht prüfen kann,
blockiert er.

### 3.9 harness/approval — Human-in-the-Loop

Drei Kategorien:

- AUTOMATIC — Log lesen, Inventarisieren, Telegram-Warnung
- REVIEW — Größere Scans, Firewall-Vorbereitung
- APPROVAL_REQUIRED — Firewall-Änderung, Blocken, Deploy

Regel: Bei Level >= 4 pausiert der Loop und wartet auf
menschliche Freigabe.

### 3.10 harness/audit — Audit-System

Append-only JSONL. Unveränderlich.

    {
      "audit_id": "AUD-2026-09-20-00001",
      "timestamp": "2026-09-20T15:33:20.123Z",
      "agent": "security_ai",
      "tool": "nmap_scan",
      "args_hash": "sha256:...",
      "policy_result": "ALLOWED",
      "permission_level": 1,
      "execution_status": "OK",
      "duration_ms": 342
    }

Regel: Kein UPDATE, kein DELETE.

### 3.11 harness/sandbox — Sandbox

**Status:** teilweise. `sandbox_profile`-Feld und
`KNOWN_SANDBOX_PROFILES` in `harness/tool_registry/tool.py`;
Profil-Dateien in `harness/sandbox/profiles/`.

**Deklaration vs. Durchsetzung (Auflage 2004):**
Die YAML-Profile sind Deklaration, nicht Durchsetzung.
Sie beschreiben `filesystem: read_only` und
`network: restricted`, aber diese beiden Aspekte werden
heute NIRGENDS zentral durchgesetzt -- weder im
AgentLoop noch im ToolRunService.

Die aktuelle Durchsetzung erfolgt pro Tool:
- `subprocess.run(..., shell=False, timeout=..., check=False)`
  (ping, traceroute, whois, nmap_scan, ...).
- `socket.settimeout(...)` (port_check).
- `check_target_allowed` (alle 5 net_diag-Tools).

Eine zentrale Sandbox-Durchsetzung
(`filesystem: read_only`, `network: restricted`)
ist geplant, aber nicht implementiert.
Zentralisierung spaeter.

Isolation pro Tool. Subprozess mit harten Limits:

- Zeit (Timeout)
- RAM (rlimit)
- CPU (rlimit)
- Netzwerk (nur autorisierte Ziele)
- Dateisystem (read-only wo möglich)

Jedes Tool hat ein Profil in harness/sandbox/profiles/.

### 3.12 harness/versioning — Change Management

Jede Änderung ist ein Change Request:

    {
      "id": "CHG-2026-00042",
      "title": "SSH: Passwort-Auth deaktivieren",
      "author": "admin_ai",
      "status": "PENDING_REVIEW",
      "risk_level": 2,
      "proposed_change": { },
      "rollback": { },
      "tests": 💡,
      "requires_approval": true
    }

Status: DRAFT -> TESTING -> PENDING_REVIEW -> APPROVED ->
DEPLOYED (oder REJECTED / ROLLED_BACK).

### 3.13 harness/context — Kontext-Bauer (Phase 3.5)

**Status:** implementiert (core/context/builder.py, Punkt 28, a2b58c1).

Baut vor jedem LLM-Aufruf einen strukturierten Kontext aus
Events, DB-Historie, Log-Ausschnitten und Inventory-Status.
Filtert Rohdaten, damit das LLM keine Freitext-Eingaben aus
unbekannten Quellen sieht (Prompt-Injection-Schutz). Der
Kontext-Bauer ist selbst auditierbar.

Das LLM bekommt nur, was der Kontext-Bauer freigibt. Kein
LLM-Output fliesst in Detection, Risk, Policy, Approval
oder Change-Freigaben.

Details: docs/DESIGN_DECISIONS.md, Abschnitt 8.

### 3.14 harness/llm — entfernt (Phase 16)

**Status:** entfernt (Phase 16).
Der ehemalige Ollama-Client (harness/llm/client.py) wurde
mit dem Ollama-Rueckbau entfernt. Siehe
DESIGN_DECISIONS Paragraph 26 und SECURITY_REVIEW_LOG
Punkt 88. Fuer Cloud-Provider siehe docs/ADMIN_AI_SCOPE.md.

### 3.15 core/reporting — Reporting & Kontext (Phase 3.5.6)

**Status:** implementiert (Phase 3.5.6).

- audit_reader.py — liest audit-logs/*.jsonl, filtert
  risk_assessments nach Zeitfenster. Kein DB-Zugriff.
- inventory_snapshot.py — reine Aggregation aus Device-Liste
  + Whitelist-Set. Kein DB-Zugriff.

Zweck: Kontext fuer den Chat aufbereiten, ohne dass der
ChatService selbst an die DB geht.

### 3.16 core/access — RBAC (Phase 3.5)

**Status:** implementiert (Phase 3.5).

- models.py — Principal, PrincipalKind, Role, Permission,
  hash_password / verify_password (pbkdf2_sha256, 600k).
- repository.py — PrincipalRepository, RoleRepository,
  PermissionRepository, RolePermissionRepository.
- checker.py — AccessChecker (check, require_permission,
  role_of, permissions_of, from_conn).

Regel: Lesen -> Checker, Schreiben -> AccessService.

### 3.16a Rollentypen und Rolleninstanzen

Der Core definiert Rollentypen (Vorlagen). Die
Admin AI darf Rolleninstanzen aus existierenden
Typen anlegen, wenn der Typ existiert und kein
Core-Admin ist. Ausnahme: Core-Admins nur durch
Menschen. Details: docs/ADMIN_AI_SCOPE.md § 4.

### 3.17 core/services — Service-Schicht (Phase 3.5)

**Status:** implementiert (Phase 3.5).

- access_service.py — AccessService (RBAC-Verwaltung,
  whoami, create_principal, assign_permission).
- ChatService (apps/security_ai/chat.py) ist
  ebenfalls Service-Schicht, liegt aber in apps/.
  ChatService ist mit dem Ollama-Rueckbau
  (Phase 16) entfernt.

Design: UI (Web/CLI/Telegram) -> Services -> Repos.
Keine Fachlogik in der UI.

### 3.18 Bridges (geplant) 💡

**Status:** geplant (Phase 7). Adapter-Muster
definiert, keine Implementierung.

Die Bridges sind **Adapter zu Cloud-Systemen**.
Sie laufen **unter** dem Core. Sie werden von ihm
**kontrolliert** und **auditiert**.

**Was eine Bridge ist:**

- Ein Adapter zu einem externen System.
- Sie kennt die API des Systems (z. B. Personio).
- Sie kennt das Schema (z. B. Personio Employee).
- Sie mappt auf das interne Schema.
- Sie laeuft in der Sandbox.
- Sie wird von der Policy Engine kontrolliert.
- Sie wird auditiert.

**Welche Bridges gibt es (geplant):**

- HR-Bridge: Personio, SAP HR, Workday.
- Buchhaltung-Bridge: DATEV, SAP FI.
- CRM-Bridge: Hubspot, Salesforce.
- Ticket-Bridge: Jira, Zendesk.
- M365-Bridge: Microsoft Graph.
- LLM-Bridges: Anthropic, OpenAI, Azure OpenAI,
  DeepSeek (alle ueber MCP).

**Was eine Bridge darf:**

- Lesen im Default.
- Schreiben nur ueber Change Request + Human
  Approval.

**Was eine Bridge NICHT darf:**

- Direkt auf Daten zugreifen (nur ueber den Core).
- Ohne Audit arbeiten.
- Ohne Policy-Check laufen.
- Ohne Sandbox laufen.

**Vorbereitbarkeit:** Bridges sind codeseitig
vorbereitbar. Die Zielsysteme (Personio, SAP HR,
Workday, DATEV, Hubspot, Jira, Microsoft Graph)
haben stabile, dokumentierte APIs. Der
Vertrauensakt ist der Betrieb beim Kunden
(Vertrag, Haftung, Versicherung, Support) -
nicht die Entwicklung des Adapters.

Siehe PROJECT_VISION § 2 (Bridge-Begriff im
Rollensicht-Bild) und docs/PHASES.md Phase 7.

## 4. Datenfluss — Beispiel

Szenario: Unbekanntes Gerät im Hauptnetz.

    1. Fritz!Box-Watcher erkennt neues Gerät
       -> erzeugt Event (event_type="device_presence")

    2. Event geht an core/inventory
       -> prüft: ist IP in whitelisted_devices?
       -> nein

    3. Event geht an core/detection
       -> Regel "unknown_main_device" greift
       -> erzeugt Detection (severity=WARNING)

    4. Detection geht an core/risk
       -> Kategorie: SECURITY_ALERT
       -> Confidence: 0.95

    5. security_ai entscheidet: Alarm senden
       -> tools/telegram_alert (Level 1)
       -> Harness prüft Permission
       -> freigegeben (Level 1 = automatisch)
       -> Telegram-Nachricht

    6. Alles wird geloggt:
       - device_logins (wer war da?)
       - security_alerts (was ist passiert?)
       - audit-logs (was hat das System getan?)

## 5. Deployment-Topologie

### 5.1 Ist-Stand 2026-09-29

    CT102 = 192.168.178.117, hostname security-ai
      - einziger aktiver Container
      - Dashboard (gunicorn 127.0.0.1:5000, nginx TLS)
      - Fritz!Box-Watcher (systemd-Timer 60s)
      - Event-Reader (systemd-Timer 30s)

    CT101 = 192.168.178.116 (ruht, bleibt unberuehrt)

Kein security-tools-LXC, kein security-db-LXC.
host_scanner ist nicht implementiert (Phase 3.8, 💡).
Alle Aktionen laufen heute lokal in CT102.

### 5.2 Ziel-Topologie (noch nicht gebaut)

    Proxmox-Host
    ├── LXC 1: security-ai          (Hauptnetz, kein Scan)
    │   ├── apps/security_ai/
    │   ├── apps/dashboard/
    │   └── apps/admin_ai/          (später)
    │
    ├── LXC 2: security-tools       (Hauptnetz, Scan erlaubt)
    │   ├── nmap
    │   ├── scapy
    │   └── isolierte Tool-Ausführung
    │
    ├── LXC 3: security-db          (internes Netz, nur DB)
    │   └── SQLite / PostgreSQL
    │
    └── Host selbst
        └── host_scanner.py         (Scapy auf vmbr0)

Regeln:

- LXC 1 hat kein CAP_NET_RAW (kein Sniffing).
- LXC 2 hat CAP_NET_RAW, aber kein Internet.
- LXC 3 ist nur von LXC 1 und 2 erreichbar.
- Host-Scanner läuft außerhalb der Container.

## 6. Sicherheitsgrenzen

| Grenze                     | Wer darf durch?                |
|----------------------------|--------------------------------|
| Modell -> System           | Niemals direkt                 |
| Modell -> Tool             | Nur über Harness               |
| Tool -> Netzwerk           | Nur autorisierte Ziele         |
| Admin AI -> Produktion     | Niemals (nur Change Requests)  |
| Security AI -> Filesystem  | Nur Lesen (kein Schreiben)     |
| LLM -> Whitelist           | Niemals                        |
| LLM -> Policies            | Niemals                        |
| LLM -> Guardrails          | Niemals                        |
| LLM -> Entscheidungen      | Niemals (nur Erklaerung)       |
| LLM -> Change-Ausfuehrung  | Niemals (Applier menschlich)   |

## 7. Erweiterbarkeit

Neue Komponenten müssen:

- Eine klare Verantwortung haben
- Ein Interface definieren
- Durch den Harness laufen (wenn sie Aktionen ausführen)
- Auditierbar sein
- Testbar ohne externe Systeme

---
Letzte Aktualisierung: 2026-10-02
