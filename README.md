# Security AI

> Ein modulares, defensives Security- und Admin-System fuer
> autorisierte IT- und Gebaeudeumgebungen. Referenz-Implementierung
> einer foederierten, KI-gestuetzten Sicherheitsarchitektur mit
> strikter Human-in-the-Loop-Kontrolle.

Stand: 2026-10-02 | HEAD: 93f6a7f | Tests: 1192 gruen (venv, pytest 9.1.1)

## Die Vision in einem Absatz

Drei KI-Ebenen. Klar getrennt. Die **Security Master AI**
(Cloud) verwaltet mehrere Kunden-Installationen. Die **Security AI**
(lokal beim Kunden) ist der zentrale Kontrollpunkt — die
einzige Schnittstelle zu allen Bridges (HR, Buchhaltung, CRM,
Tickets, M365, LLMs). Die **Kunden-Mitarbeiter-KI** assistiert
dem Endnutzer in natuerlicher Sprache.

Der Mensch entscheidet. Die KI schlaegt vor, erklaert und
korreliert. Jede Aktion ist auditierbar und umkehrbar.
Vom lokalen Security-Tool ueber foederierte Netzwerke bis zur
Enterprise-Plattform — mit Human-in-the-Loop, lueckenlosem
Audit und DSGVO-konform.

Die vollstaendige Vision: [PROJECT_VISION.md](PROJECT_VISION.md).

## Was das System heute kann

- **Netzwerk-Ueberwachung:** Erkennt unbekannte Geraete,
  Gast-WLAN-Aktivitaet, Port-Scans und Web-Reconnaissance.
- **Geraete-Inventar:** Weiss, welche Geraete erlaubt sind und
  welche nicht. SQLite-basiert, mit Historie.
- **Detection Engine:** Deterministische Regeln
  (unknown_device, unknown_device_persistent, network_change,
  mac_change, device_flapping, port_scan). Kein LLM.
- **Risk Engine:** Deterministische Bewertung. Score aus Basis
  plus Modifikatoren. Nachvollziehbar.
- **ntfy-Alarme:** Self-hosted Push-Kanal (Tailnet) auf
  Proxmox-Host, F-Droid-App auf Android. Telegram bleibt
  optional als Fallback (Punkt 76).
- **RBAC:** Drei unabhaengige Skalen (Raum, Tool, Daten) mit
  feinkoernigen Permissions.
- **Lokale KI (Ollama):** llama3.2:3b fuer schnelle Erklaerungen,
  qwen2.5:7b fuer tiefe Fragen (Auto-Switch). Keine Cloud,
  keine Datenabfluesse.
- **Chat mit der Security AI:** Fragen in natuerlicher Sprache
  ("Gab es heute Nacht Auffaelligkeiten?"). Fact-Pfad
  deterministisch (Labels statt Rohkategorien, dynamischer
  Zeitraum), Interpretations-Pfad mit Auto-Switch und
  Sanity-Check.
- **Approval Queue:** Level-4-Aktionen warten auf
  Human-Approval.
- **Change Requests:** Aenderungen mit Diff, Rollback, Tests.
- **Audit-Log:** Append-only JSONL. Jede Aktion unveraenderlich
  protokolliert.
- **Web-Dashboard:** Flask-basiert, RBAC, CSP-konform.
  Seiten: Dashboard, Inventar, Alarme, Approvals, Changes,
  Chat, Benutzer, Rollen, Audit, Einstellungen, Suche.
  Links im Chat (Objekt-Referenzen und Navigations-Hinweise).
- **HTTPS hinter nginx** mit eigener CA, gunicorn (2 Worker).
- **1191 Tests, alle gruen.**

## Was gerade gebaut wird

- Alarm-Runde (Punkte 70-74) abgeschlossen:
  unknown_device_persistent (Zeit-Eskalation),
  network_change, mac_change, device_flapping,
  known aus Whitelist.
- Punkte 75 (internal_name + IP-Suche),
  77 (ntfy-Benachrichtigungssystem),
  79 + 79a (Alarme-Seite Klartext + Links),
  56a (Whitelist-Pflege) abgeschlossen.
- Lizenz AGPL-3.0-or-later durchgaengig
  (LICENSE, pyproject, Copyright-Header in
  205 .py-Dateien).
- Offen: 80 (Alarme-Filter + Pagination),
  57 (Guardrails), 58 (Werkzeuge-Werkbank),
  76 (Telegram, optional).
- Phasen 5-11 in Planung (siehe Was geplant ist).

## Was geplant ist

- **Stufe 3:** Foederation — mehrere Netzwerke, zentrale
  Security Master AI.
- **Stufe 4:** Enterprise — Bridges zu HR, Buchhaltung, CRM,
  Tickets, M365, LLMs. Kunden-Mitarbeiter-KI. DSGVO-Konformitaet.
- **Stufe 5:** Physische Sicherheit — RFID, Zutritt, Raum-Level.
- **Stufe 6:** Ganzheitliche Korrelation — digital + physisch.

## Architektur (Rollensicht)

Vier Rollen, ein zentraler Core:

    +---------------------------------------------------------+
    |  MENSCH (letzte Instanz)                                |
    |  Entscheidet bei Risiko >= 2. Whitelist-Pflege.         |
    +---------------------------------------------------------+
                              ^
                              |
    +--------------------------+------------------------------+
    |  ADMIN AI (Cloud, Sicherheit)                           |
    |  KUNDEN-KI (Cloud, Mitarbeiter-Aufgaben)                |
    |  Intelligenz-Schicht. Asynchron.                        |
    |  Vorschlaege, Change Requests. Kein Direktzugriff.      |
    +--------------------------+------------------------------+
                              ^
                              |
    +--------------------------v------------------------------+
    |  CORE (BIOS, Bridge, Anker)                             |
    |  Deterministisch, 24/7, kein LLM.                      |
    |  Watcher, Detektoren, Risk, RBAC, Audit, Approval.      |
    |  Einzige Schnittstelle zu allen Geraeten und Diensten.  |
    +--------------------------+------------------------------+
                              |
    +--------------------------v------------------------------+
    |  GERAETE, NETZ, EXTERNE DIENSTE                         |
    |  Datenquellen und Aussenwelt.                           |
    +---------------------------------------------------------+

Drei Blickwinkel auf dieselbe Architektur:
- Technische Schichten: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (5-1).
- Rollen im Betrieb: diese Sicht (Mensch, Cloud, Core, Geraete).
- Test-Ebenen: [docs/DESIGN_DECISIONS.md](docs/DESIGN_DECISIONS.md) (1-5).

## Sicherheit

- **Whitelist** ist manuell und Mensch-only.
- **Capabilities** werden im Security-Container entzogen.
- **Guardrails** sind Code, nicht Prompt.
- **Audit-Logs** sind append-only, unveraenderlich.
- **Keine Shell-Ausfuehrung** durch das Modell.
- **Prompt-Injection** wird im Policy-Layer geblockt.
- **Human-in-the-Loop** ist Pflicht bei Risiko >= 2.
- **DSGVO-Konformitaet** ist Pflicht.

Details: [docs/SECURITY.md](docs/SECURITY.md)

## Dokumentation

- [Projekt-Vision](PROJECT_VISION.md) — die grosse Vision
- [Architektur](docs/ARCHITECTURE.md) — 4-Ebenen-Modell
- [Sicherheit](docs/SECURITY.md) — Threat Model, Guardrails
- [Berechtigungen](docs/PERMISSIONS.md) — Level 0-5
- [Protokoll](docs/PROTOCOL.md) — Foederation (MCP)
- [Deployment](docs/DEPLOYMENT.md) — Proxmox-Setup
- [Design-Entscheidungen](docs/DESIGN_DECISIONS.md) — 40+ Entscheidungen
- [ntfy-Betrieb](docs/NTFY.md) — Push-Kanal auf Proxmox-Host
- [Phasen](docs/PHASES.md) — Skalierungspfad
- [Werkzeuge](docs/WERKZEUGE.md) — Skripte und CLIs
- [Web-Security-Checkliste](docs/WEB_SECURITY_CHECKLIST.md) — verbindliche Checkliste
- [Security-Review-Log](docs/SECURITY_REVIEW_LOG.md) — Entscheidungen und offene Punkte
- [Workflow](docs/WORKFLOW.md) — Prozess, Hard-Rules
