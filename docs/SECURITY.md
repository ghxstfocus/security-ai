# Sicherheit — Homelab Security AI

> Threat Model, Guardrails, Prompt-Injection-Schutz,
> Audit-Anforderungen und Sicherheitsgrenzen.

## 1. Sicherheitsphilosophie

Drei Grundsätze:

1. **Defense in Depth.** Mehrere Schichten. Wenn eine versagt,
   greift die nächste.
2. **Fail closed.** Wenn etwas nicht geprüft werden kann,
   wird blockiert. Nicht durchgelassen.
3. **Least Privilege.** Jede Komponente hat nur die Rechte,
   die sie wirklich braucht.

## 2. Threat Model

### 2.1 Was wir schützen

- **Daten:** Events, Geräte-Inventar, Logs, Audit-Trail
- **Systeme:** Der Security-Container und seine Umgebung
- **Netzwerk:** Das Homelab und seine Geräte
- **Entscheidungen:** Die Kontrolle über Whitelist und Policies

### 2.2 Wer sind die Angreifer

| Angreifer                | Ziel                                  |
|--------------------------|---------------------------------------|
| Externe Scanner          | Offene Ports, Schwachstellen finden   |
| Kompromittiertes Gerät   | Im LAN lateral bewegen                |
| Prompt-Injection via Log | Das LLM zu unerlaubten Aktionen bringen |
| Neugieriger Nutzer       | Whitelist manipulieren                |
| Fehlerhafter Code        | Unerlaubte Aktionen ausführen         |

### 2.3 Was sind die Risiken

- **Unbefugter Zugriff** auf Dashboard, Webhook, DB
- **Prompt-Injection** durch manipulierte Logs oder Events
- **Capability-Eskalation** im Container
- **Datenabfluss** durch Cloud-Modelle
- **Autonome Aktionen** ohne menschliche Freigabe
- **Manipulation** der Whitelist oder Audit-Logs

## 3. Guardrails

Guardrails sind **Code**, nicht Prompt. Sie sind nicht durch das
Modell überschreibbar. Sie werden vor **jedem** Tool-Aufruf
ausgeführt.

### 3.1 scope_guard

**Zweck:** Verhindert Scans oder Aktionen außerhalb der
autorisierten Netzbereiche.

**Regel:**

    AUTHORIZED_NETWORKS = [
        "192.168.178.0/24",   # Hauptnetz
        "192.168.189.0/24",   # Gastnetz
        "127.0.0.1/32",       # Loopback
    ]

Jeder Ziel-IP wird geprüft. Wenn sie nicht in einem dieser Netze
liegt: **Blockiert**.

### 3.2 self_mod_guard

**Zweck:** Verhindert, dass das Modell seine eigenen Policies
oder Guardrails ändert.

**Geschützt:**

- harness/guardrails/*
- harness/permissions/*
- policies/*.yaml

Jeder Schreibzugriff auf diese Pfade: **Blockiert**.

### 3.3 audit_guard

**Zweck:** Verhindert, dass das Audit-System deaktiviert oder
manipuliert wird.

**Geschützt:**

- audit-logs/*
- harness/audit/writer.py

Jeder Versuch, Audit-Logs zu löschen oder zu ändern: **Blockiert**.

### 3.4 prompt_injection_guard

**Status:** teilweise implementiert (Phase 3.5) als
`harness/context/redaction.py`. Vollstaendige Version
(Guardrail im Harness) spaeter.

Aktuelle Implementierung:
- Steuerzeichen entfernen (\x00, \r, \x0b, \x0c).
- Instruktions-Marker entfernen (case-insensitive):
  "ignore previous", "system:", "assistant:", "user:",
  "<|im_start|>", "###instruction", "[INST]", "<<SYS>>".
- Laengenbegrenzung pro Feld (Default 2000 Zeichen).
- redacted-Flag im ContextBundle.

Der Kontext-Bauer filtert Rohdaten, bevor sie ans LLM gehen.
Das LLM bekommt nur, was der Kontext-Bauer freigibt.

### 3.5 RBAC als zweite Ebene (Phase 3.5)

Neben Tool-Level 0-5 gibt es seit Phase 3.5 eine zweite
Berechtigungsebene: rollenbasierte Principals.

- Principal: alles, was authentifiziert werden kann
  (human, system, service).
- Rollen: admin, operator, viewer, system.
- Permissions: chat.ask, approval.decide, principal.manage,
  usw.
- Fail closed: unbekannter Principal oder Permission-Code
  -> Ablehnung.

Details: `docs/PERMISSIONS.md` § 13.

## 4. Human-in-the-Loop

### 4.1 Drei Kategorien

| Kategorie            | Beschreibung                          | Beispiel              |
|----------------------|---------------------------------------|-----------------------|
| AUTOMATIC            | Sofort erlaubt                        | Log lesen, Alarm senden |
| REVIEW               | Wartet auf Review vor Ausführung      | Größerer Scan          |
| APPROVAL_REQUIRED    | Wartet auf explizite Freigabe         | Firewall-Änderung      |

### 4.2 Zuordnung

Die Zuordnung erfolgt über das **Permission-Level** des Tools:

| Tool-Level | Human-in-the-Loop-Kategorie |
|------------|-----------------------------|
| 0          | AUTOMATIC                   |
| 1          | AUTOMATIC                   |
| 2-3        | REVIEW                      |
| 4          | APPROVAL_REQUIRED           |
| 5          | FORBIDDEN                   |

### 4.3 Ablauf bei APPROVAL_REQUIRED

    1. Agent Loop erreicht einen Tool-Aufruf mit Level 4
    2. Loop pausiert
    3. Change Request wird in changes/ abgelegt
    4. Mensch wird benachrichtigt (Telegram / Dashboard)
    5. Mensch entscheidet: APPROVED / REJECTED
    6. Bei APPROVED: Loop setzt fort
    7. Bei REJECTED: Loop beendet sich, Audit-Eintrag

## 5. Capabilities und Isolation

### 5.1 Container-Aufteilung

| Container | Zweck               | Capabilities               |
|-----------|---------------------|----------------------------|
| LXC 1     | security-ai         | KEIN NET_RAW, KEIN NET_ADMIN |
| LXC 2     | security-tools      | NET_RAW, NET_ADMIN          |
| LXC 3     | security-db         | KEINE                       |
| Host      | host_scanner        | NET_RAW (außerhalb LXC)     |

### 5.2 LXC-Config für LXC 1

In /etc/pve/lxc/102.conf:

    lxc.cap.drop = net_raw net_admin sys_admin
    lxc.cap.drop = sys_module sys_ptrace

Damit kann der Security-Container **nichts** sniffen, scannen oder
das System manipulieren. Tools laufen im separaten LXC 2.

### 5.3 LXC-Config für LXC 2

In /etc/pve/lxc/103.conf:

    lxc.cap.keep = net_raw net_admin
    lxc.net.0.type = veth
    lxc.net.0.link = vmbr0
    lxc.net.0.flags = up

Dieser Container darf scannen — aber hat **keinen** Internetzugang.

## 6. Secrets und Credentials

### 6.1 Grundregeln

- **Niemals** Secrets im Git-Repo.
- **Niemals** Secrets in Logs.
- **Niemals** Secrets in Telegram-Nachrichten.
- `.env` ist in `.gitignore`.
- `.env.example` enthält nur Platzhalter.

### 6.2 Wo Secrets liegen dürfen

- .env im Container (Datei-Rechte: 600)
- Systemd-Environment-Dateien
- (später) Vault oder ähnliche Lösung

### 6.3 Rotation

Alle Secrets sollten regelmäßig rotiert werden:

- `SECRET_KEY` — bei jedem Vorfall
- `WEBHOOK_TOKEN` — alle 90 Tage
- `TELEGRAM_BOT_TOKEN` — bei Verdacht
- `PROXMOX_TOKEN_SECRET` — bei Verdacht

### 6.4 Principal-Credentials (Phase 3.5)

Principals koennen optional ein Passwort haben
(password_hash, Migration 0005).

- Hashing: pbkdf2_sha256, 600_000 Iterationen (OWASP 2023).
- Format: pbkdf2_sha256$600000$<salt_hex>$<hash_hex>.
- In Phase 3.5 nicht genutzt: cli-admin laeuft ohne Login
  (lokal auf dem Server).
- Login kommt mit Web-Dashboard (Phase 3.6).
- Systeme (security_ai, host_scanner) haben kein Passwort.
- Passwort-Wechsel: `PrincipalRepository.set_password_hash`.

## 7. Audit-System

### 7.1 Anforderungen

- **Append-only.** Kein UPDATE, kein DELETE.
- **Unveränderlich.** Nach dem Schreiben nicht manipulierbar.
- **Vollständig.** Jede Aktion wird geloggt.
- **Zeitgestempelt.** ISO-8601 mit Zeitzone.
- **Zuordenbar.** Wer (Agent), was (Tool), wann (Zeit), warum
  (Policy-Ergebnis).

### 7.2 Format

JSONL — ein Eintrag pro Zeile, in audit-logs/YYYY-MM-DD.jsonl.

Beispiel:

    {
      "audit_id": "AUD-2026-09-20-00001",
      "timestamp": "2026-09-20T15:33:20.123Z",
      "agent": "security_ai",
      "network_id": "homelab-ct101",
      "tool": "nmap_scan",
      "args_hash": "sha256:abc123...",
      "policy_result": "ALLOWED",
      "permission_level": 1,
      "execution_status": "OK",
      "duration_ms": 342,
      "output_hash": "sha256:def456..."
    }

### 7.3 Aufbewahrung

- Mindestens 90 Tage online
- Danach: komprimiert archivieren
- Nach 1 Jahr: prüfen, ob noch nötig

## 8. Logging vs. Audit

Wichtiger Unterschied:

| Logging                       | Audit                          |
|-------------------------------|--------------------------------|
| Für Debugging                 | Für Sicherheit                 |
| Kann rotiert werden           | Append-only, unveränderlich    |
| Nicht beweisrelevant          | Beweisrelevant                 |
| Format frei                   | Format standardisiert          |

Logs sind für den Entwickler. Audit ist für den Sicherheitsnachweis.

## 9. Netzwerk-Segmentierung

### 9.1 Heute

Ein Container im Hauptnetz. Alle Aktionen sind lokal.

### 9.2 Ziel

    Proxmox-Host
    ├── LXC 1: security-ai      — Hauptnetz, kein Scan
    ├── LXC 2: security-tools   — Hauptnetz, Scan erlaubt
    ├── LXC 3: security-db      — internes Netz, nur DB
    └── Host: host_scanner      — Bridge-Sniffing

Zwischen LXC 1 und LXC 2: Unix-Socket oder internes HTTPS mit
Client-Zertifikat. Kein direkter Shell-Zugriff.

## 10. Incident Response

Wenn ein Sicherheitsvorfall erkannt wird:

1. **Alarm** wird ausgelöst (Telegram).
2. **Event** wird in security_alerts geloggt.
3. **Audit-Eintrag** wird geschrieben.
4. **Keine automatische Blockade** — Mensch entscheidet.
5. **Mensch prüft** die Details im Dashboard.
6. **Mensch entscheidet**: Ignorieren / Blocken / Eskalieren.
7. **Jede Entscheidung** wird auditiert.

## 11. Was das System NICHT tut

- Keine autonomen Firewall-Änderungen.
- Keine automatischen Blocks ohne Freigabe.
- Kein Versand von Secrets an Cloud-Dienste.
- Kein Zugriff auf Dateien außerhalb definierter Pfade.
- Kein Ausführen von Shell-Befehlen durch das Modell.
- Kein Selbst-Update ohne Change Request.

## 12. Sicherheits-Checkliste

Vor jedem Deployment:

- [ ] .env nicht im Repo
- [ ] Alle Secrets gesetzt und stark
- [ ] Guardrails aktiv
- [ ] Audit-System schreibt
- [ ] Capabilities korrekt gesetzt
- [ ] Firewall-Regeln geprüft
- [ ] Logs rotieren
- [ ] Backups funktionieren

---
Letzte Aktualisierung: 2026-09-20
