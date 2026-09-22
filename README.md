# Homelab Security AI

> Modulares, defensives Security- und Admin-System für autorisierte
> IT-Umgebungen. Referenz-Implementierung einer föderierten,
> KI-gestützten Sicherheitsarchitektur mit strikter
> Human-in-the-Loop-Kontrolle.

## Was ist das?

Ein lauffähiges Security-Monitoring-System für mein Homelab, das
bewusst als kleine, saubere Referenz angelegt ist. Es erkennt:

- Unbekannte Geräte im Hauptnetz
- Gast-WLAN-Aktivität (sichtbar, kein Alarm)
- Port-Scans (SYN, FIN, XMAS, NULL, UDP)
- HTTP-Reconnaissance (Scanner-User-Agents, verdächtige Pfade, 404-Wellen)

Alarme per Telegram. Alles landet in einer strukturierten SQLite-DB
als Grundlage für spätere KI-gestützte Analyse.

## Warum ist das interessant?

Das System denkt Architektur mit:

- **4-Ebenen-Modell:** Human -> Admin AI -> Harness -> Security AI -> Tools
- **Guardrails als Code**, nicht als Prompt
- **Deterministische Detection** (LLM nur für Erklärung, nicht Bewertung)
- **Append-only Audit**
- **Human-in-the-Loop** dreistufig (AUTOMATIC, REVIEW, APPROVAL)
- **Föderationsprotokoll** (MCP-basiert) für spätere Multi-Netzwerk-Nutzung

Es ist kein vollautonomes System. Es ist eine kontrollierte
Augmentation menschlicher Administratoren.

## Aktueller Stand

- [x] Netzwerk-Inventar (Fritz!Box, Docker, Proxmox)
- [x] Whitelist-basierte Erkennung
- [x] Gastnetz-Erkennung ohne Alarm
- [x] Port-Scan-Erkennung (Scapy)
- [x] HTTP-Recon-Erkennung (Flask)
- [x] Telegram-Alarme
- [x] SQLite-Event-Datenbank
- [x] systemd-Service
- [x] Policy Engine (Allowed / Approval / Forbidden)
- [x] Approval-Flow + Change Requests (SQLite, CLI)
- [x] Lokales LLM (Ollama, llama3.2:3b + qwen2.5:7b)
- [x] RBAC (Principals, Rollen, Permissions)
- [x] Frage-Klassifikation (fact / concept / interpretation)
- [x] Chat-CLI (`scripts/chat_cli.py`)
- [ ] Web-Dashboard (Phase 3.6)
- [ ] Admin AI
- [ ] Föderation (Multi-Netzwerk)

## Architektur

4-Ebenen-Modell: Human -> Admin AI -> Harness -> Security AI -> Tools.
Details: `docs/ARCHITECTURE.md`

## Sicherheit

- **Whitelist** ist manuell und Mensch-only
- **Capabilities** werden im Security-Container entzogen
- **Tools** laufen in isolierten Containern
- **Guardrails** sind Code, nicht Prompt
- **Audit-Logs** sind append-only
- **Keine Shell-Ausführung** durch das Modell
- **Human-in-the-Loop** ist Pflicht bei Risiko >= 2

Details: `docs/SECURITY.md`

## Dokumentation

- [Projekt-Vision](PROJECT_VISION.md)
- [Architektur](docs/ARCHITECTURE.md)
- [Sicherheit](docs/SECURITY.md)
- [Protokoll](docs/PROTOCOL.md)
- [Berechtigungen](docs/PERMISSIONS.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Design-Entscheidungen](docs/DESIGN_DECISIONS.md)
- [Phasen](docs/PHASES.md)
- [Werkzeuge](docs/WERKZEUGE.md)

## Status

Aktiv in Entwicklung. Homelab-Referenz mit dem Ziel, die
Architektur für föderierte, KI-gestützte Security- und
Admin-Systeme zu demonstrieren.

Letzte Aktualisierung: 2026-09-22
