# Homelab Security AI — Projekt-Vision

> Ein modulares, defensives Security- und Admin-System für
> autorisierte IT-Umgebungen. Entwickelt als Referenz-Implementierung
> für eine föderierte, KI-gestützte Sicherheitsarchitektur mit
> strikter Human-in-the-Loop-Kontrolle.

## 1. Kurzbeschreibung

Das System erkennt unbekannte Geräte, Gast-WLAN-Aktivität,
Port-Scans und Web-Reconnaissance in einem Homelab. Es sammelt
strukturierte Events, bewertet sie deterministisch, alarmiert per
Telegram und legt die Daten als Grundlage für eine spätere
KI-gestützte Analyse aus.

Das Projekt ist bewusst als kleine, lauffähige Referenz angelegt —
mit der Architektur, die später auf mehrere Netzwerke und
Unternehmensumgebungen skaliert werden kann.

## 2. Übergeordnetes Ziel

Eine Admin AI als "Head of Operations" für mehrere voneinander
isolierte Netzwerke. Lokale Security AIs liefern Events, die
Admin AI korreliert, bewertet und Change Requests vorschlägt.
Der Mensch entscheidet. Jede Aktion ist auditierbar und umkehrbar.

Ziel ist nicht autonome KI, sondern kontrollierte Augmentation
menschlicher Administratoren — mit klaren Grenzen, Guardrails und
nachvollziehbaren Entscheidungen.

## 3. Grundprinzipien

1. Mensch behält Kontrolle. Kritische Entscheidungen (Whitelist,
   Firewall, Deployments) sind immer Human-Approval-pflichtig.
2. Defense in Depth. Determinismus wo möglich, KI nur wo nötig.
3. Eine Quelle der Wahrheit. Policies, Whitelist, Events — je
   genau ein Ort.
4. Append-only Audit. Jede Aktion unveränderlich protokolliert.
5. Fail closed. Wenn ein Guardrail nicht prüfen kann, blockiert er.
6. Keine Cloud-Abhängigkeit im Kern. Lokale Modelle, lokale Daten.
7. Föderation statt Monolith. Jedes Netzwerk eigenständig, das
   Admin AI optional.

## 4. Zielarchitektur (4-Ebenen-Modell)

## 5. Skalierungspfad

**Stufe 1 — Homelab (heute)**
Ein Netzwerk, eine Security AI, lokales Modell.
Deterministische Detection, Telegram-Alarme.

**Stufe 2 — Erweiterung (Monate)**
Change-Request-Generator, lokales LLM für Erklärungen,
Human-in-the-Loop mit Approval-Queue.

**Stufe 3 — Föderation (später)**
Mehrere isolierte Netzwerke, zentrales Admin AI (Cloud),
standardisiertes Protokoll (MCP-basiert).

**Stufe 4 — Enterprise-Bridges (Zukunft)**
Anbindung an Anthropic / OpenAI / eigene Cloud-LLMs,
standardisierte Schnittstellen, Zertifizierungen.

## 6. Datenmodell (heute)

SQLite (homelab_history.db):

- `whitelisted_devices`  — manuell gepflegte Whitelist (Mensch only)
- `device_logins`        — lückenloses Log aller gesehenen Geräte
- `security_alerts`      — Vorfälle (unknown_device, guest_device,
                            port_scan, http_recon)
- `system_history`       — Infrastruktur-Snapshots
- `error_logs`           — Fehler

## 7. Alarm-Regeln

| Ereignis                                | Telegram | DB  |
|-----------------------------------------|----------|-----|
| Gastgerät im Gastnetz                   | nein     | ja  |
| Bekanntes Gerät im Hauptnetz            | nein     | ja  |
| Unbekanntes Gerät im Hauptnetz          | ja (W)   | ja  |
| Whitelist-Gerät macht Port-Scan         | ja (C)   | ja  |
| Externe IP macht Port-Scan              | ja (C)   | ja  |
| HTTP-Recon (nmap-UA, verd. Pfad, 404)   | ja (W)   | ja  |

W = WARNING, C = CRITICAL

## 8. Security-Prinzipien

- Whitelist ist manuell und Mensch-only.
- Capabilities werden im Security-Container entzogen.
- Guardrails sind Code, nicht Prompt.
- Audit-Logs sind append-only JSONL, unveränderlich.
- Keine Shell-Ausführung durch das Modell.
- Prompt-Injection wird im Policy-Layer geblockt.
- Human-in-the-Loop ist Pflicht bei Risiko-Level >= 2.

## 9. Nicht-Ziele

- Kein automatisches Blocken von IPs ohne Freigabe.
- Kein LLM-Schreibzugriff auf Policies, Whitelist oder Guardrails.
- Keine Cloud-Abhängigkeit im Kern.
- Kein autonomer Deploy in Produktion.
- Keine Fremdsystem-Scans außerhalb autorisierter Netzbereiche.

## 10. Referenzen

- Architektur: docs/ARCHITECTURE.md
- Sicherheit: docs/SECURITY.md
- Protokoll: docs/PROTOCOL.md
- Berechtigungen: docs/PERMISSIONS.md
- Deployment: docs/DEPLOYMENT.md

---
Letzte Aktualisierung: 2026-09-20
