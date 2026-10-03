# Homelab Security AI — Project Vision

> Ein lokales Security-System, das deterministisch
> arbeitet, wenn Sicherheit zaehlt, und LLMs nur
> dort einsetzt, wo sie erklaeren helfen.

Stand: 2026-10-03 | HEAD: 057cc3f

---

## 1. Warum dieses Projekt

Das Projekt entstand aus einer einfachen
Beobachtung: KI ist dann wertvoll, wenn sie
dort eingesetzt wird, wo sie hilft —
Erklaerungen, Zusammenfassungen, natuerliche
Sprache. Sie ist dann gefaehrlich, wenn sie
Entscheidungen trifft, die schnell,
nachvollziehbar und reproduzierbar sein
muessen.

Klassische Security-Tools sind entweder starr
(reine Regelwerke, kein Kontext) oder
Blackboxes (Cloud-KI, keine Nachvollziehbarkeit).
Dieses Projekt zieht die Linie bewusst: alles,
was schnell und verlaesslich sein muss, laeuft
deterministisch. Alles, was erklaeren und
formulieren muss, darf ein LLM nutzen.

Der Mensch bleibt die letzte Instanz.

## 2. Wie es aussieht

    +=================================================================+
    |  MENSCH (letzte Instanz)                                        |
    |  Entscheidet bei Risiko >= 2.                                   |
    +================================+================================+
                                     |
                                     |  Freigabe
                                     v
    +=================================================================+
    |  ADMIN AI (Cloud, optional)  |  KUNDEN-KI (Cloud, optional)     |
    |  Sicherheit, Korrelation     |  Mitarbeiter-Aufgaben            |
    |  Vorschlaege, Changes        |  Fragen, Schreibvorschlaege      |
    +================================+================================+
                                     |
                                     |  Vorschlag
                                     v
    +=================================================================+
    |  CORE (lokal, deterministisch, 24/7)                            |
    |                                                                 |
    |  - Detection Engine (regelbasiert, kein LLM)                    |
    |  - Risk Engine (deterministisch, kein LLM)                      |
    |  - Inventory (Geraete, Personen, Whitelist)                     |
    |  - RBAC (drei Skalen: Raum, Tool, Daten)                        |
    |  - Policy Engine (was darf was)                                 |
    |  - Guardrails (was darf NIEMALS)                                |
    |  - Sandbox (isolierte Ausfuehrung)                              |
    |  - Audit (append-only, unveraenderlich)                         |
    |  - Approval Queue (Human-in-the-Loop)                           |
    |  - Change Request Workflow                                      |
    |  - Lokales LLM (Ollama, optional)                               |
    |                                                                 |
    |  = SCHNITTSTELLE zu ALLEN Bridges                               |
    |  = einzige Instanz, die Aktionen ausfuehrt                      |
    +================================+================================+
                                     |
                                     |  Aktion
                                     v
    +=================================================================+
    |  GERAETE, NETZ, SYSTEME, EXTERNE DIENSTE                        |
    |  Fritz!Box, Docker, Proxmox, Sensoren, RFID                     |
    |  Bridges: HR, Buchhaltung, CRM, Tickets, M365, LLMs             |
    +=================================================================+

Der Core ist das **BIOS** des Systems: basal,
deterministisch, immer da. Er entscheidet nicht,
er liefert Zustand. Er ist die **Bridge** zu
allen Geraeten und Diensten und der **Anker**,
an dem jede Aktion haengt.


## 3. Drei Blickwinkel

Die Architektur laesst sich aus drei
Perspektiven betrachten. Keine ist "wahrer"
als die andere.

**Technische Schichten** (docs/ARCHITECTURE.md):
Ebene 5 bis 1 — Tools, Security AI, Harness,
Admin AI, Mensch.

**Rollen im Betrieb** (dieses Dokument):
Mensch, Admin AI, Core, Kunden-KI, Geraete.

**Test-Ebenen** (docs/DESIGN_DECISIONS.md):
Score, Mapping, Kette, Approval, Change.

Die drei Blickwinkel beschreiben dieselbe
Architektur. Wer neu in das Projekt einsteigt,
liest zuerst die Rollensicht (hier), dann die
technischen Schichten (ARCHITECTURE.md).

## 4. Grundprinzipien

1. **Determinismus wo es zaehlt.** Detection,
   Risk und Policy sind regelbasiert. Kein LLM.
   Nachvollziehbar, reproduzierbar.

2. **LLM nur fuer Erklaerung.** Der lokale Chat,
   die Cloud-Analysen. Nie fuer Entscheidungen.

3. **Human-in-the-Loop.** Jede Aktion mit
   Risiko >= 2 braucht menschliche Freigabe.
   Der Approval laeuft im Chat, nicht auf
   einer separaten Seite.

4. **Fail closed.** Wenn eine Pruefung nicht
   moeglich ist: blockieren, nicht durchlassen.

5. **Defense in Depth.** Guardrails, Policy,
   RBAC, Sandbox, Audit — mehrere Schichten
   unabhaengig voneinander.

6. **Guardrails sind Code, nicht Prompt.**
   Keine Umgehung durch Prompt-Injection.

7. **Autarkie.** Kein Cloud-Zwang. Das System
   laeuft lokal, 24/7, ohne externe
   Abhaengigkeiten.

## 5. Der Ausfuehrungspfad

Jede KI im System (Admin AI, Kunden-KI, Chat,
spaetere) folgt demselben Pfad:

    Vorschlag -> Bestaetigung -> Core prueft
      -> Applier fuehrt aus -> Audit

Kein LLM entscheidet. Kein LLM schreibt direkt.
Jede Aktion laeuft durch den Core. Der Core
prueft gegen Policy und Berechtigungen. Der
Applier fuehrt aus. Das Audit dokumentiert.

Der Approval laeuft im Chat: der Mensch sieht
den Vorschlag, bestaetigt, und die Ausfuehrung
startet. Token-basiert (einmalig, zeitlich
begrenzt, an Nutzer und Aktion gebunden).


## 6. Was heute laeuft

Status-Marker: ✅ laeuft, 🔨 in Arbeit,
💡 geplant.

| Feature                        | Status | Hinweis                              |
|--------------------------------|--------|--------------------------------------|
| Detection Engine (Regeln)      | ✅     | 6 Regeln, deterministisch            |
| Risk Engine                    | ✅     | Score, reproduzierbar                |
| Inventory (Geraete, Whitelist) | ✅     | MAC als Identitaet                   |
| RBAC (3 Skalen)                | ✅     | Rollen, Permissions, Sessions        |
| Policy Engine                  | ✅     | globale + spezifische Pruefer        |
| Guardrails                     | 🔨     | globale Pruefer, Erweiterung geplant |
| Audit (append-only)            | ✅     | JSONL, unveraenderlich               |
| Approval Queue                 | ✅     | CLI + Chat-Approval geplant          |
| Change Requests                | ✅     | ChangeService + CLI                  |
| Change Applier                 | 🔨     | Stub, echte Implementierung geplant  |
| Fritz!Box-Watcher              | ✅     | 60s-Timer, Systemd                   |
| Event-Reader                   | ✅     | 30s-Timer, Systemd                   |
| ntfy-Alarme                    | ✅     | self-hosted, Tailscale               |
| Web-Dashboard                  | ✅     | RBAC, CSP-konform, 12 Seiten         |
| Lokaler Chat (Ollama)          | ✅     | optional, Fact/Concept/Interpretation|
| Host-Scanner                   | 💡     | Phase 3.8                            |
| Admin AI (Cloud)               | 💡     | Phase 5                              |
| Kunden-KI (Cloud)              | 💡     | Phase 9                              |
| Data Connectors                | 💡     | Phase 7                              |
| Physische Sicherheit           | 💡     | Phase 10                             |
| Korrelation (digital+physisch) | 💡     | Phase 11                             |

Testabdeckung: 1208 Tests, alle gruen.


## 7. Was es nicht tut

- Keine autonomen Firewall-Aenderungen.
- Kein Auto-Block ohne Freigabe.
- Kein Cloud-Zwang.
- Kein LLM in Entscheidungen.
- Kein Selbst-Update ohne Change Request.
- Kein Zugriff ausserhalb definierter Pfade.
- Keine personenbezogenen Entscheidungen
  durch KI.

## 8. Naechste Schritte

1. Change Applier implementieren
   (Voraussetzung fuer alle Ausfuehrungen).
2. Chat als Aktions-Schnittstelle
   (Approval im Chat).
3. Host-Scanner (Phase 3.8).
4. Sofort-Massnahmen-Kategorie
   (ISOLATE, BLOCK, KILL).
5. Admin AI als Cloud-Schicht.


## 9. Ausblick

Vom lokalen Homelab ueber foederierte Netzwerke
bis zur Enterprise-Plattform. Der Core bleibt
derselbe. Die KIs kommen dazu. Der Mensch
entscheidet immer.

Details zu den Phasen: docs/PHASES.md.

## 10. Referenzen

- docs/ARCHITECTURE.md — technische Schichten.
- docs/SECURITY.md — Threat Model, Guardrails,
  Alarm-Regeln.
- docs/PHASES.md — Phasenstand und Roadmap.
- docs/DESIGN_DECISIONS.md — Design-Entscheidungen.
- docs/PERMISSIONS.md — Tool-Level und RBAC.
- docs/PROTOCOL.md — Foederationsprotokoll.
- docs/WORKFLOW.md — Prozess und Regeln.

