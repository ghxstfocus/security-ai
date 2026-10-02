# Homelab Security AI — Projekt-Vision

> Ein modulares, defensives Security- und Admin-System fuer
> autorisierte IT- und Gebaeudeumgebungen. Referenz-Implementierung
> einer foederierten, KI-gestuetzten Sicherheitsarchitektur mit
> strikter Human-in-the-Loop-Kontrolle.

## 1. Das grosse Bild

Ein Security-System, das lokal beim Betreiber laeuft.
Vier Rollen, klar getrennt.

Der **Core** ist der harte Kern. Er laeuft lokal,
deterministisch, 24/7. Er entscheidet nicht - er
liefert Zustand und fuehrt aus, was der Mensch
freigegeben hat.

Die **Admin AI** ist die Sicherheits-KI in der Cloud
(optional). Sie korreliert Events ueber mehrere
Installationen, schlaegt Changes vor. Sie fuehrt nichts
selbst aus.

Die **Kunden-KI** ist die KI fuer die Mitarbeiter
des Kunden (Cloud, optional). Sie assistiert in
natuerlicher Sprache, alles laeuft durch den Core.

Der **Mensch** ist die letzte Instanz. Jede
kritische Aktion braucht seine Freigabe.

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
    |  - RBAC (3 Skalen: Raum, Tool, Daten)                           |
    |  - Policy Engine (was darf was)                                 |
    |  - Guardrails (was darf NIEMALS)                                |
    |  - Sandbox (isolierte Ausfuehrung)                              |
    |  - Audit (append-only, unveraenderlich)                         |
    |  - Approval Queue (Human-in-the-Loop)                           |
    |  - Change Request Workflow                                      |
    |  - Lokales LLM (Ollama) fuer Erklaerungen                       |
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
    |  Bridges: HR, Buchhaltung, CRM, Tickets,                        |
    |  M365, LLMs                                                     |
    +=================================================================+

Der **gemeinsame Ausfuehrungspfad** aller KIs:

    Vorschlag -> Bestaetigung -> Core prueft
      -> Applier fuehrt aus -> Audit

Kein LLM entscheidet. Kein LLM schreibt direkt.
Jede Aktion laeuft durch den Core.

## 2.0 Drei Blickwinkel auf dieselbe Architektur

Dieses Dokument spricht in drei Blickwinkeln. Sie
beschreiben dieselbe Architektur, nicht drei Modelle.

### Technische Schichten (5-1)

Ebene 5 Tools & Infrastruktur, 4 Security AI (Core),
3 Builder Harness, 2 Admin AI, 1 Human Admin.
Details: docs/ARCHITECTURE.md.

### Rollen im Betrieb (dieses Dokument)

Vier Rollen:
- Mensch (letzte Instanz, oben).
- Admin AI (Cloud, Sicherheit) und Kunden-KI
  (Cloud, Mitarbeiter-Aufgaben) — zwei Cloud-Rollen
  mit verschiedenem Zweck, gleicher Ausfuehrungspfad.
- Core (BIOS, Bridge, Anker, lokal). Der Core heisst
  in dieser Rolle auch 'das BIOS'. Analog wie ein BIOS
  im Rechner ist er basal, deterministisch, immer da.
  Er entscheidet nicht, er liefert Zustand.
- Geraete, Netz, externe Dienste (Aussenwelt, unten).

### Test-Ebenen (1-5)

Score-Regeln, Kategorie-Mapping, Kette, Approval,
Change Requests. Details: docs/DESIGN_DECISIONS.md.

## 2. Die Rollen im Detail

### 2.1 Admin AI (Cloud, Sicherheit)

Die Admin AI ist die **Sicherheits-KI der IT Firma**.
Sie laeuft in der Cloud. Sie ist optional - das
System funktioniert autark ohne sie.

**Was sie macht:**

1. **Installationen verwalten.** Sie kennt mehrere
   Installationen des Betreibers. Welche Version
   laeuft? Welche Bridges sind aktiv? Welche Events
   gibt es?

2. **Ueber Installationen korrelieren.** Sie sieht
   Events aus mehreren Installationen. Sie erkennt
   Muster ueber Installationen hinweg.

3. **Changes vorschlagen.** Sie schlaegt Changes
   fuer Installationen vor. Der Mensch gibt frei.

4. **Mit externen LLMs sprechen.** Ueber MCP. Sie
   kann Anthropic, OpenAI, Azure OpenAI, DeepSeek
   anbinden - je nach Aufgabe und
   Datenschutz-Anforderung.

**Was sie NICHT macht:**

- Kein Kontakt zu Endnutzer-Mitarbeitern.
- Kein Zugriff auf Rohdaten (nur Aggregate).
- Keine Aktionen ohne Human Approval.
- Keine personenbezogenen Entscheidungen.
- Keine direkte Ausfuehrung.

**Ausfuehrungspfad:** Die Admin AI folgt demselben
Pfad wie jede andere KI im System: Vorschlag ->
Bestaetigung durch den Menschen -> Core prueft ->
Applier fuehrt aus -> Audit. Sie fuehrt nichts
selbst aus.

**Kurz:** Die Admin AI ist der **Kopf der IT Firma**.
Sie koordiniert, korreliert, schlaegt vor. Sie hat
nichts mit den Mitarbeitern der Kunden zu tun.

### 2.2 Core (lokal, deterministisch)

Der Core ist das **BIOS des Systems**: basal,
deterministisch, immer da. Er entscheidet nicht,
er liefert Zustand. Er ist auch die **Bridge** zu
allen Geraeten und Diensten und der **Anker**, an
dem jede Aktion haengt.

Der Core laeuft **lokal beim Betreiber** im
Container. Er ist der **zentrale Hub** - alles
laeuft durch ihn. Nichts an ihm vorbei.

**Was er macht:**

1. **Detection.** Er liest Events von Sensoren
   (Fritz!Box, Netzwerk, Docker, Proxmox, Logs,
   RFID, Tueren). Er wendet **deterministische
   Regeln** an. Kein LLM.

2. **Risk Engine.** Er bewertet Events
   **deterministisch**. Score aus Basis +
   Modifikatoren. Kein LLM. Nachvollziehbar.

3. **Inventory.** Er kennt Geraete, Personen,
   Whitelist.

4. **RBAC.** Drei unabhaengige Skalen:
   - Raum-Level (physischer Zutritt)
   - Tool-Level (digitaler Zugriff)
   - Daten-Level (Sichtbarkeit)
   Kein Level ist automatisch von einem anderen
   abhaengig.

5. **Policy Engine.** Er weiss, welches Tool unter
   welchen Bedingungen erlaubt ist. Globale Pruefer
   (Shell-Injection, Path-Traversal) laufen immer.

6. **Guardrails.** Er weiss, was **NIEMALS** erlaubt
   ist. Das ist Code, nicht Prompt.

7. **Sandbox.** Er fuehrt Tools **isoliert** aus.
   Timeouts, rlimits, kein Shell.

8. **Audit.** Er schreibt **jede** Aktion in ein
   append-only JSONL-Log. Unveraenderlich.

9. **Approval Queue.** Er legt Aktionen mit Risiko
   >= 2 in eine Queue. Der Mensch entscheidet.

10. **Change Request Workflow.** Er erstellt
    Antraege fuer Aenderungen. Mit Diff, Rollback,
    Tests.

11. **Lokales LLM (Ollama, optional).** llama3.2:3b
    fuer schnelle Erklaerungen, qwen2.5:7b fuer tiefe
    Fragen (Auto-Switch). Nur fuer Erklaerungen,
    nie fuer Entscheidungen.

12. **Schnittstelle zu allen Bridges.** Er ist die
    **einzige** Instanz, die Bridges aufruft. Keine
    andere Komponente spricht direkt mit einer
    Bridge.

13. **Kontrolliert die Kunden-KI.** Er prueft jede
    Anfrage, bevor sie an die Kunden-KI
    weitergegeben wird (siehe 2.3).

**Was er NICHT macht:**

- Kein LLM in Entscheidungen.
- Keine direkten Systemaenderungen ohne Approval.
- Keine Whitelist-Aenderungen.
- Keine Policies aendern.
- Kein Zugriff ausserhalb autorisierter Bereiche.
- Keine Scans ohne Harness.
- Keine personenbezogenen Entscheidungen.
- Keine Cloud-Abhaengigkeit.

**Ausfuehrungspfad:** Der Core ist die Stelle, an
der jede Aktion geprueft und ausgefuehrt wird.
Er empfaengt Vorschlaege von den KIs (Admin AI,
Kunden-KI) oder vom Menschen, prueft sie gegen
Policy und Berechtigungen, fuehrt sie bei
Freigabe aus und auditiert.

**Kurz:** Der Core ist die **kontrollierte
Ausfuehrungsumgebung** und der **zentrale Hub**.
Er entscheidet nichts ueber Menschen. Er fuehrt
aus, was der Mensch freigegeben hat.

### 2.3 Kunden-KI (Cloud, Mitarbeiter-Aufgaben)

Die Kunden-KI ist die **KI fuer die Mitarbeiter des
Kunden**. Sie ist die Schnittstelle zwischen Mensch
und Daten. Sie ist optional - der Core funktioniert
autark ohne sie.

**Was sie macht:**

1. **Fragen entgegennehmen.** Jeder Mitarbeiter fragt
   in natuerlicher Sprache ("Wie viele Urlaubstage
   habe ich?", "Zeig mir Urlaub von Mueller.",
   "Trage Urlaub 01.10.-05.10. ein.").

2. **Kontext verstehen.** Sie kennt den Principal
   (wer fragt), die Rolle, die Berechtigungen.

3. **An den Core uebergeben.** Jede Anfrage geht
   an den Core. Der Core entscheidet, was erlaubt
   ist. Die Kunden-KI entscheidet nichts.

4. **Antworten formulieren.** Sie formuliert die
   Antwort in natuerlicher Sprache.

5. **Schreibaktionen vorschlagen.** Sie schlaegt
   Change Requests vor ("Trage Urlaub ein"). Der
   Mensch gibt frei.

**Was sie NICHT macht:**

- Kein direkter Datenzugriff. Alles ueber den Core.
- Keine Aktionen ohne Approval.
- Keine Entscheidungen ueber Personen.
- Keine Umgehung des Core.

**Ausfuehrungspfad:** Die Kunden-KI folgt demselben
Pfad wie jede andere KI im System: Vorschlag ->
Bestaetigung durch den Menschen -> Core prueft ->
Applier fuehrt aus -> Audit. Sie fuehrt nichts
selbst aus.

**Kurz:** Die Kunden-KI ist der **Assistent des
Endnutzers**. Sie ist die einzige KI, mit der
Endnutzer-Mitarbeiter direkt sprechen.

## 3. Die Bridges — die Cloud-Anbindungen

Die Bridges sind **Adapter zu Cloud-Systemen**. Sie
laufen **unter** dem Core. Sie werden von ihm
**kontrolliert** und **auditiert**.

**Was eine Bridge ist:**

- Ein **Adapter** zu einem externen System.
- Sie kennt die **API** des Systems (z. B. Personio).
- Sie kennt das **Schema** (z. B. Personio Employee).
- Sie **mappt** auf das interne Schema.
- Sie laeuft in der **Sandbox**.
- Sie wird von der **Policy Engine** kontrolliert.
- Sie wird **auditiert**.

**Welche Bridges gibt es:**

- **HR-Bridge:** Personio, SAP HR, Workday.
- **Buchhaltung-Bridge:** DATEV, SAP FI.
- **CRM-Bridge:** Hubspot, Salesforce.
- **Ticket-Bridge:** Jira, Zendesk.
- **M365-Bridge:** Microsoft Graph (E-Mail, Kalender,
  Teams, SharePoint).
- **LLM-Bridges:** Anthropic, OpenAI, Azure OpenAI,
  DeepSeek (alle ueber MCP).

**Was eine Bridge darf:**

- **Lesen** im Default.
- **Schreiben** nur ueber Change Request + Human
  Approval.

**Was eine Bridge NICHT darf:**

- Direkt auf Daten zugreifen (nur ueber den Core).
- Ohne Audit arbeiten.
- Ohne Policy-Check laufen.
- Ohne Sandbox laufen.

**Vorbereitbarkeit:** Bridges sind codeseitig
vorbereitbar. Die Zielsysteme (Personio, SAP HR,
Workday, DATEV, Hubspot, Jira, Microsoft Graph)
haben stabile, dokumentierte APIs. Ein Adapter
kann gegen die oeffentliche API-Doku gebaut und
gegen einen Sandbox-Account getestet werden.
Der Vertrauensakt ist der **Betrieb** beim Kunden
(Vertrag, Haftung, Versicherung, Support) — nicht
die Entwicklung des Adapters. Deshalb koennen
Bridges parallel zum Core entstehen.

**Der Datenfluss:**

    Core (prueft)
      -> Bridge (verbindet)
        -> Externes System (liefert Daten)
      <- Bridge (mappt)
    <- Core (auditiert, antwortet)

## 4. Wie die Rollen zusammenspielen

### Beispiel 1 — Kunden-Mitarbeiter fragt

    Mitarbeiter (Buchhaltung):
      "Zeig mir Urlaub von Mueller."

    Kunden-KI:
      - Versteht die Frage
      - Leitet an Core weiter

    Core:
      - Prueft RBAC: Rolle "buchhaltung" -> darf HR lesen?
      - Prueft Daten-Level: Urlaub = Level 2
      - Ergebnis: JA
      - Waehlt Bridge: HR-Bridge (Personio)
      - Ruft Bridge auf
      - Bridge holt Daten: "Mueller, 12 Tage uebrig"
      - Audit-Eintrag
      - Antwort an Mitarbeiter-KI

    Kunden-KI:
      "Mueller hat 12 Tage uebrig."

### Beispiel 2 — Kunden-Mitarbeiter weist an

    Mitarbeiter (Buchhaltung):
      "Trage ihm Urlaub vom 01.10. bis 05.10. ein."

    Kunden-KI:
      - Versteht: Schreibaktion
      - Leitet an Core weiter

    Core:
      - Prueft RBAC: Rolle "buchhaltung" -> darf schreiben?
      - Ergebnis: JA (mit Approval)
      - Erstellt Change Request
      - Legt in Approval Queue
      - Wartet

    Human Admin (Mensch):
      - Sieht Change Request
      - Prueft Datum, Person
      - Gibt frei

    Core:
      - Ruft HR-Bridge auf
      - Bridge schreibt: "Urlaub 01.10.-05.10. fuer Mueller"
      - Audit-Eintrag
      - Antwort an Mitarbeiter-KI

### Beispiel 3 — Mitarbeiter fragt eigene Daten

    Mitarbeiter:
      "Wie viele Urlaubstage habe ich?"

    Kunden-KI:
      - Versteht: eigene Daten
      - Leitet an Core weiter

    Core:
      - Prueft Principal: max.mustermann
      - Sonderfall "self": nur eigene Daten
      - Ergebnis: JA
      - Ruft HR-Bridge auf
      - Antwort: "Du hast 8 Tage uebrig."

### Beispiel 4 — IT Firma fragt Kunden-Status

    IT Firma (Admin):
      "Zeig mir alle Kunden mit kritischen Events."

    Admin AI:
      - Versteht: Aggregat ueber alle Kunden
      - Fragt jede Installation: "Kritische Events?"
      - Installation: prueft, antwortet aggregiert
      - Antwort: "3 Kunden mit kritischen Events."
      - KEIN Zugriff auf einzelne Personen.

## 5. Die Reise in einem Satz

Vom lokalen Homelab ueber foederierte Netzwerke
bis zur Enterprise-Plattform. Der Core bleibt
derselbe: deterministisch, lokal, 24/7. Die KIs
kommen dazu (Admin AI fuer Sicherheit, Kunden-KI
fuer Mitarbeiter). Der Mensch entscheidet immer.

## 6. Kurzbeschreibung

Das System erkennt unbekannte Geraete, Netz-Wechsel,
MAC-Wechsel und Flattern in einem Netzwerk. Port-Scan-
Regeln sind vorhanden, der Producer (Host-Scanner)
fehlt noch (Phase 3.8).

Es bewertet Ereignisse deterministisch und alarmiert
per ntfy (self-hosted).

Physische Zutrittsereignisse (RFID, Magnetkarte,
PIN, optional Biometrie) sind als Phase 10
vorgesehen, aber noch nicht implementiert.

Besonders wichtig: Das System korreliert **digitale
und physische Sicherheit** (Phase 11). Es erkennt
Zusammenhaenge, die einzelne Systeme niemals sehen
wuerden.

Das Projekt ist bewusst als kleine, lauffaehige
Referenz angelegt - mit der Architektur, die
spaeter auf mehrere Netzwerke, Gebaeude und
Unternehmensumgebungen skaliert werden kann.

## 7. Grundprinzipien

1. **Mensch behaelt Kontrolle.** Kritische Entscheidungen
   sind immer Human-Approval-pflichtig.
2. **Defense in Depth.** Mehrere Schichten.
3. **Determinismus wo moeglich, KI nur wo noetig.**
   Detection ist regelbasiert. Das LLM erklaert, plant
   und schlaegt vor — es bewertet nicht.
4. **Autarkie.** Jeder lokale Core funktioniert
   ohne die Admin AI.
5. **Eine Quelle der Wahrheit.** Policies, Whitelist,
   Events — je genau ein Ort.
6. **Append-only Audit.** Jede Aktion unveraenderlich
   protokolliert.
7. **Fail closed.** Wenn ein Guardrail nicht pruefen
   kann, blockiert er.
8. **Keine Cloud-Abhaengigkeit im Kern.** Lokale
   Modelle, lokale Daten.
9. **Foederation statt Monolith.** Jedes Netzwerk/
   Gebaeude eigenstaendig.
10. **Physisch-digital vereint.**
11. **DSGVO-Konformitaet ist Pflicht.**
12. **Ein zentraler Hub.** Der Core ist die
    einzige Schnittstelle zu allen Bridges. Nichts
    laeuft an ihr vorbei.

## 8. Skalierungspfad

### Stufe 1 — Netzwerk Homelab (heute)
Ein Netzwerk. Ein Core. Keine Admin
AI. Keine Kunden-KI.
Status (2026-09-26): [x] implementiert (Commit f986ba2).

### Stufe 2 — Erweiterung (Monate)
Change-Request-Generator. Approval-Queue. Lokales LLM.
Status (2026-09-26): [x] implementiert (Commit f986ba2).

### Stufe 2.5 — Lokale KI (Monate)
Ollama, Chat, RBAC, Auto-Switch.
Status (2026-09-26): [x] implementiert (Commit f986ba2).

### Stufe 3 — Foederation (spaeter)
Mehrere isolierte Netzwerke. Zentrale Security
AI (Cloud). MCP-Protokoll.
Pro Netzwerk eigene Credentials, eigene Policies.

### Stufe 4 — Enterprise (Zukunft)
Drei Themen, die zusammengehoeren:

**Enterprise-Bridges.**
Der Core wird zur zentralen Schnittstelle
fuer alle Cloud-Systeme des Kunden (HR, Buchhaltung,
CRM, Tickets, M365, LLMs). Jede Bridge ist ein
Adapter. Nichts laeuft am Core vorbei.

**Kunden-KI.**
Die KI fuer die Mitarbeiter des Kunden. Jeder
Mitarbeiter fragt in natuerlicher Sprache. Die KI
liest Daten ueber den Core, schlaegt
Schreibaktionen vor, der Mensch gibt frei. Jeder
sieht nur seine Rolle-relevanten Daten.

**DSGVO-Konformitaet.**
Privacy by Design, Zweckbindung, Datenminimierung,
Loeschfristen, Betroffenenrechte, Verzeichnis von
Verarbeitungstaetigkeiten, TOMs, AVV-Vorlagen.
Lueckenlos. Kein Kompromiss.

Status (2026-09-26): [ ] geplant.

### Stufe 5 — Physische Sicherheit (Zukunft)
RFID, Magnetkarte, PIN, optional Biometrie.
Raum-Level, Tool-Level, Daten-Level unabhaengig.
Personen als Entitaeten.

### Stufe 6 — Ganzheitliche Korrelation (Zukunft)
Digitale und physische Sicherheit verheiratet.
Korrelationsregeln (access_level_mismatch,
digital_without_physical, access_after_departure, ...).

## 9. Physische Sicherheit (Stufe 5)

### 9.1 Raum-Sicherheitslevel (0-5)

| Level | Bedeutung         | Beispiel                       |
|-------|-------------------|--------------------------------|
| 0     | Oeffentlich       | Empfang, Flure                 |
| 1     | Niedrig           | Besucherbereiche               |
| 2     | Normal            | Bueros, Mitarbeiterbereiche    |
| 3     | Erhoeht           | IT, Management                 |
| 4     | Hoch              | Serverraum, Tresor             |
| 5     | Kritisch          | Sicherheitszentrale, Vorstand  |

### 9.2 Zutrittstechnologien
RFID, Magnetkarte, PIN, optional Biometrie.
Plugin-System fuer Erweiterungen. Einheitliches
Event-Schema.

### 9.3 Personen als Entitaeten
ID, Name, Typ, Raum-Level, Tool-Level, Zeit-
einschraenkungen, Zutrittshistorie.

### 9.4 Korrelationsregeln
access_level_mismatch, access_outside_hours,
digital_without_physical, physical_without_digital,
access_after_departure, unusual_pattern, tailgating.

### 9.5 Ethische Leitplanken (verbindlich)
Keine Gesichtserkennung ohne Freigabe.
Keine biometrischen Daten ohne Zustimmung.
Keine Bewegungsprofile.
Keine dauerhafte Speicherung ohne Zweck.
Transparenz, Zweckbindung, Loeschfristen,
Zugriffskontrolle.

## 10. MCP-Kopplung an externe LLMs

Die Admin AI und der Core sprechen
ueber **MCP** mit externen LLMs. Erlaubt:

- Wahl des Modells pro Aufgabe
- Anbindung durch Firmen an ihre eigene KI
- Wechsel ohne Neuentwicklung
- Kostenoptimierung

Beide fungieren als **Vermittler** zwischen lokalem
Sicherheitssystem und KI-Landschaft.

## 11. Datenmodell

### 11.1 Heute (Stufe 1)
SQLite (`data/inventory.db`): whitelisted_devices,
device_logins, security_alerts, system_history,
error_logs, approvals, change_requests, roles,
permissions, role_permissions, principals,
schema_migrations.

### 11.2 Ziel (Stufe 4+)
persons, rooms, access_events, access_permissions,
tool_permissions, data_permissions, correlations,
external_mappings.

### 11.3 Events sind einheitlich
Alle Events — digital und physisch — nutzen das
gleiche Schema.

## 12. Alarm-Regeln

### 12.1 Digital
Gastgeraet: kein Alarm. Bekanntes Geraet: kein Alarm.
Unbekanntes Geraet im Hauptnetz: Telegram (W).
Port-Scan von Whitelist oder extern: Telegram (C).
HTTP-Recon: Telegram (W).

### 12.2 Physisch
Zutritt erfolgreich: kein Alarm. Zutritt verweigert:
Telegram (W). Raum-Level-Mismatch: Telegram (C).
Zutritt ausserhalb Arbeitszeit: Telegram (W).
Tailgating: Telegram (W). Tuer offen: Telegram (W).

### 12.3 Korreliert
Login ohne Zutritt: Telegram (C). Zugriff bleibt
aktiv: Telegram (W). Ungewoehnliches Muster: Telegram
(W). System bleibt offen: Telegram (W). Mehrere
Versuche: Telegram (C).

## 13. Security-Prinzipien

- Whitelist ist manuell und Mensch-only.
- Capabilities werden im Security-Container entzogen.
- Guardrails sind Code, nicht Prompt.
- Audit-Logs sind append-only JSONL.
- Keine Shell-Ausfuehrung durch das Modell.
- Prompt-Injection wird im Policy-Layer geblockt.
- Human-in-the-Loop ist Pflicht bei Risiko >= 2.
- DSGVO-Konformitaet ist Pflicht.
- Ein zentraler Hub: Der Core ist die einzige
  Schnittstelle zu allen Bridges.

## 14. Nicht-Ziele

- Kein automatisches Blocken ohne Freigabe.
- Kein LLM-Schreibzugriff auf Policies, Whitelist,
  Guardrails, Zutrittsberechtigungen oder
  Personaldaten.
- Keine Cloud-Abhaengigkeit im Kern.
- Kein autonomer Deploy in Produktion.
- Keine Fremdsystem-Scans ausserhalb autorisierter
  Bereiche.
- Keine Gesichtserkennung ohne ausdrueckliche Freigabe.
- Keine Bewegungsprofile von Personen.
- Keine biometrischen Daten ohne Zustimmung.
- Keine Zweckentfremdung von Zutrittsdaten oder
  Personaldaten.
- Keine KI-Entscheidung ueber Personen ohne Mensch.

## 15. Warum dieses Projekt

Ich habe jahrelang nichts mit IT oder Coden zu tun
gehabt. Nach einer Pause habe ich einen Proxmox-Server
aufgesetzt, einen Container erstellt — und gemerkt,
dass ich ein System bauen moechte, das ich selbst im
Alltag brauchen kann.

Der Anlass war praktisch: Ich wollte wissen, wer sich
in meinem Netzwerk befindet, und ich wollte Alarme,
wenn etwas Verdaechtiges passiert. Aus dieser
praktischen Notwendigkeit ist eine Architektur
entstanden, die weit ueber ein Homelab-Tool
hinausgeht.

Ich glaube, dass KI-gestuetzte Sicherheit mit
Human-in-the-Loop die Zukunft ist — nicht autonome
KI, sondern **verstaerkte menschliche Entscheidungen**.

## 16. Wo die Reise endet

Am Ende steht eine foederierte, KI-gestuetzte
Sicherheits- und Verwaltungsplattform, die:

- Mehrere Netzwerke und Gebaeude verbindet.
- Digitale und physische Sicherheit korreliert.
- Mitarbeitern aus allen Bereichen den Zugriff auf
  die fuer sie relevanten Daten gibt - in
  natuerlicher Sprache, ueber die Kunden-KI.
- Personalverwaltung, HR-Daten, Buchhaltung und
  Sicherheit zusammenfuehrt - mit strikter
  RBAC-Kontrolle und DSGVO-Konformitaet.
- An externe Cloud-KIs ueber offizielle Protokolle
  angebunden werden kann (MCP) - oder autark lokal
  laeuft, wenn Cloud nicht gewuenscht ist.
- Jede Aktion auditiert, jede Entscheidung
  menschlich freigegeben, jede Aenderung umkehrbar.

Vier Rollen. Klar getrennt. Der Core bleibt der
harte Kern - lokal, deterministisch, kein LLM in
Entscheidungen. Die Admin AI (Cloud, optional)
korreliert ueber Installationen und schlaegt
Changes vor. Die Kunden-KI (Cloud, optional)
assistiert Endnutzern. Der Mensch ist immer die
letzte Instanz.

## 17. Referenzen

- Architektur: docs/ARCHITECTURE.md
- Sicherheit: docs/SECURITY.md
- Protokoll: docs/PROTOCOL.md
- Berechtigungen: docs/PERMISSIONS.md
- Deployment: docs/DEPLOYMENT.md
- Phasen: docs/PHASES.md
- Design-Entscheidungen: docs/DESIGN_DECISIONS.md
- Security-Review-Log: docs/SECURITY_REVIEW_LOG.md
- Workflow: docs/WORKFLOW.md

---
Letzte Aktualisierung: 2026-09-26

