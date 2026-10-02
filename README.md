# Security AI

> Ein modulares, defensives Security- und Admin-System fuer
> autorisierte IT- und Gebaeudeumgebungen. Referenz-Implementierung
> einer foederierten, KI-gestuetzten Sicherheitsarchitektur mit
> strikter Human-in-the-Loop-Kontrolle.

Stand: 2026-10-02 | HEAD: 413540e | Tests: 1191 gruen (venv, pytest 9.1.1)

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
- **Detection Engine:** Deterministische Regeln (unknown_device,
  port_scan, http_recon). Kein LLM.
- **Risk Engine:** Deterministische Bewertung. Score aus Basis
  plus Modifikatoren. Nachvollziehbar.
- **Telegram-Alarme:** Sofort-Benachrichtigung bei
  Sicherheitsvorfaellen.
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
- **1028 Tests, alle gruen.**

## Was gerade gebaut wird

- A900 abgeschlossen: mypy no-untyped-def
  66 -> 2, ruff 2 -> 0. Offen: Punkt 60
  (mypy orchestrator.py).
- Punkt 11 (SSH-Zugang Windows -> CT102) — Betriebsakt.
- Phasen 5-11 in Planung (siehe Was geplant ist).

## Was geplant ist

- **Stufe 3:** Foederation — mehrere Netzwerke, zentrale
  Security Master AI.
- **Stufe 4:** Enterprise — Bridges zu HR, Buchhaltung, CRM,
  Tickets, M365, LLMs. Kunden-Mitarbeiter-KI. DSGVO-Konformitaet.
- **Stufe 5:** Physische Sicherheit — RFID, Zutritt, Raum-Level.
- **Stufe 6:** Ganzheitliche Korrelation — digital + physisch.

## Architektur (Kurzfassung)

Drei KI-Ebenen, ein zentraler Hub:

    +---------------------------------------------------------+
    |  SECURITY MASTER AI (Cloud)                             |
    |  Verwaltet mehrere Kunden-Installationen.               |
    |  Nichts mit Endkunden-Mitarbeitern zu tun.              |
    +-------------------------+-------------------------------+
                              |
    +-------------------------v-------------------------------+
    |  SECURITY AI (lokal, Kunde)                             |
    |  = KONTROLLSCHICHT                                      |
    |  = SCHNITTSTELLE zu ALLEN Bridges                       |
    |  Detection, Risk, RBAC, Guardrails, Audit, Approval.    |
    +-------------------------+-------------------------------+
                              |
    +-------------------------v-------------------------------+
    |  BRIDGES                                                |
    |  HR, Buchhaltung, CRM, Tickets, M365, LLMs.             |
    |  Lesen im Default, Schreiben nur mit Approval.          |
    +-------------------------+-------------------------------+
                              |
    +-------------------------v-------------------------------+
    |  KUNDEN-MITARBEITER-KI                                  |
    |  Assistent fuer Endnutzer.                              |
    |  Nur was Security AI freigibt.                          |
    +---------------------------------------------------------+

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
- [Phasen](docs/PHASES.md) — Skalierungspfad
- [Werkzeuge](docs/WERKZEUGE.md) — Skripte und CLIs
- [Web-Security-Checkliste](docs/WEB_SECURITY_CHECKLIST.md) — verbindliche Checkliste
- [Security-Review-Log](docs/SECURITY_REVIEW_LOG.md) — Entscheidungen und offene Punkte
- [Workflow](docs/WORKFLOW.md) — Prozess, Hard-Rules
