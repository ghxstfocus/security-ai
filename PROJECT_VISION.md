# Homelab Security AI — Projekt-Vision

> Ein modulares, defensives Security- und Admin-System fuer
> autorisierte IT- und Gebaeudeumgebungen. Referenz-Implementierung
> einer foederierten, KI-gestuetzten Sicherheitsarchitektur mit
> strikter Human-in-the-Loop-Kontrolle.

## 1. Das grosse Bild

Drei KI-Ebenen. Klar getrennt. Jede mit eigener Rolle.
Die Security AI ist der zentrale Kontrollpunkt. Alles
laeuft durch sie. Nichts an ihr vorbei.

    +=================================================================+
    |  EBENE 1 — IT Firma (intern)                                   |
    |                                                                 |
    |  SECURITY MASTER AI (Cloud)                                     |
    |  - Verwaltet die Kunden-Installationen der IT Firma            |
    |  - Korreliert Events ueber mehrere Kunden                       |
    |  - Schlaegt Changes fuer Kunden vor                             |
    |  - Spricht mit externen LLMs (MCP)                              |
    |  - Hat NICHTS mit Endkunden-Mitarbeitern zu tun                 |
    +================================+================================+
                                     |
                                     |  Verwaltung, Monitoring
                                     v
    +=================================================================+
    |  EBENE 2 — KUNDE (lokal beim Kunden)                            |
    |                                                                 |
    |  SECURITY AI (Core, lokal) = KONTROLLSCHICHT                    |
    |                                                                 |
    |  Aufgaben:                                                      |
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
    |                                                                 |
    |  Was sie kontrolliert:                                          |
    |  - Jede Bridge                                                  |
    |  - Jede Anfrage                                                 |
    |  - Jede Schreibaktion                                           |
    |                                                                 |
    |  WICHTIG: Sie entscheidet nichts ueber Menschen.                |
    |           Sie fuehrt aus, was der Mensch freigegeben hat.       |
    +================================+================================+
                                     |
          +--------------------------+--------------------------+
          |                          |                          |
          v                          v                          v
    +--------------+    +-------------------+    +-------------------+
    |  KUNDEN-     |    |  BRIDGES (Cloud)  |    |  DATA CONNECTORS  |
    |  MITARBEITER-|    |                   |    |  (falls lokal)    |
    |  KI          |    |  HR-Bridge        |    |                   |
    |              |    |  (Personio,       |    |  Optional fuer    |
    |  - Endnutzer |    |   SAP HR,         |    |  On-Prem-Systeme  |
    |    fragen    |    |   Workday)        |    |                   |
    |  - Nur was   |    |                   |    |                   |
    |    Security  |    |  Buchhaltung-     |    |                   |
    |    AI frei-  |    |  Bridge           |    |                   |
    |    gibt      |    |  (DATEV, SAP)     |    |                   |
    |              |    |                   |    |                   |
    |  - Schlaegt  |    |  CRM-Bridge       |    |                   |
    |    Schreib-  |    |  (Hubspot,        |    |                   |
    |    aktionen  |    |   Salesforce)     |    |                   |
    |    vor       |    |                   |    |                   |
    |              |    |  Ticket-Bridge    |    |                   |
    |              |    |  (Jira, Zendesk)  |    |                   |
    |              |    |                   |    |                   |
    |              |    |  M365-Bridge      |    |                   |
    |              |    |  (Microsoft Graph)|    |                   |
    |              |    |                   |    |                   |
    |              |    |  LLM-Bridges      |    |                   |
    |              |    |  (Anthropic,      |    |                   |
    |              |    |   OpenAI,         |    |                   |
    |              |    |   Azure OpenAI,   |    |                   |
    |              |    |   DeepSeek)       |    |                   |
    +--------------+    +-------------------+    +-------------------+
                                     |
                                     |  Cloud-API-Aufrufe
                                     v
    +=================================================================+
    |  EXTERNE CLOUD-SYSTEME                                          |
    |                                                                 |
    |  HR, Buchhaltung, CRM, Ticketsystem, M365, LLM-Provider         |
    +=================================================================+

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

## 2. Die drei KI-Ebenen — im Detail (Rollen im Betrieb)

### 2.1 Security Master AI (Ebene 1 — IT Firma, Cloud)

Die Security Master AI ist die **Admin-KI der IT Firma**.
Sie laeuft in der Cloud. Sie verwaltet die **Kunden-
Installationen** der IT Firma.

**Was sie macht:**

1. **Kunden verwalten.** Sie kennt alle Kunden-
   Installationen der IT Firma. Welche Version laeuft?
   Welche Bridges sind aktiv? Welche Events gibt es?

2. **Ueber Kunden korrelieren.** Sie sieht Events aus
   mehreren Kunden-Installationen. Sie erkennt Muster
   ueber Kunden hinweg ("drei Kunden haben heute
   denselben Port-Scan-Typ gesehen").

3. **Changes vorschlagen.** Sie schlaegt Changes fuer
   Kunden vor ("Kunde A sollte seine Firewall-Regel
   anpassen"). Der Mensch gibt frei.

4. **Mit externen LLMs sprechen.** Ueber MCP. Sie kann
   Anthropic, OpenAI, Azure OpenAI, DeepSeek anbinden.
   Je nach Aufgabe und Datenschutz-Anforderung.

**Was sie NICHT macht:**

- **Kein Kontakt zu Endkunden-Mitarbeitern.**
- Kein Zugriff auf Endkunden-Daten (nur Aggregate).
- Keine Aktionen ohne Human Approval.
- Keine personenbezogenen Entscheidungen.

**Kurz:** Die Security Master AI ist der **Kopf der
IT Firma**. Sie koordiniert, korreliert, schlaegt vor.
Sie hat nichts mit den Mitarbeitern der Kunden zu tun.

### 2.2 Security AI (Ebene 2 — Kunde, lokal) — Der zentrale Hub

Die Security AI ist die **Kontrollschicht**. Sie laeuft
**lokal beim Kunden** im Container. Sie ist der
**zentrale Hub** — alles laeuft durch sie. Nichts an
ihr vorbei.

**Was sie macht:**

1. **Detection.** Sie liest Events von Sensoren
   (Netzwerk, Fritz!Box, Docker, Proxmox, Logs, RFID,
   Tueren). Sie wendet **deterministische Regeln** an.
   Kein LLM. Klare Regeln.

2. **Risk Engine.** Sie bewertet Events
   **deterministisch**. Score aus Basis + Modifikatoren.
   Kein LLM. Nachvollziehbar.

3. **Inventory.** Sie kennt Geraete, Personen,
   Whitelist.

4. **RBAC.** Drei unabhaengige Skalen:
   - Raum-Level (physischer Zutritt)
   - Tool-Level (digitaler Zugriff)
   - Daten-Level (Sichtbarkeit)
   Kein Level ist automatisch von einem anderen
   abhaengig.

5. **Policy Engine.** Sie weiss, welches Tool unter
   welchen Bedingungen erlaubt ist. Globale Pruefer
   (Shell-Injection, Path-Traversal) laufen immer.

6. **Guardrails.** Sie weiss, was **NIEMALS** erlaubt
   ist. Das ist Code, nicht Prompt.

7. **Sandbox.** Sie fuehrt Tools **isoliert** aus.
   Timeouts, rlimits, kein Shell.

8. **Audit.** Sie schreibt **jede** Aktion in ein
   append-only JSONL-Log. Unveraenderlich.

9. **Approval Queue.** Sie legt Aktionen mit Risiko
   >= 2 in eine Queue. Der Mensch entscheidet.

10. **Change Request Workflow.** Sie erstellt Antraege
    fuer Aenderungen. Mit Diff, Rollback, Tests.

11. **Lokales LLM (Ollama).** llama3.2:3b fuer schnelle
    Erklaerungen, qwen2.5:7b fuer tiefe Fragen
    (Auto-Switch).

12. **Schnittstelle zu allen Bridges.** Sie ist die
    **einzige** Instanz, die Bridges aufruft. Keine
    andere Komponente spricht direkt mit einer Bridge.

13. **Kontrolliert die Kunden-Mitarbeiter-KI.** Sie
    prueft jede Anfrage, bevor sie an die Mitarbeiter-
    KI weitergegeben wird.

**Was sie NICHT macht:**

- Keine direkten Systemaenderungen ohne Approval.
- Keine Whitelist-Aenderungen.
- Keine Policies aendern.
- Kein Zugriff ausserhalb autorisierter Bereiche.
- Keine Scans ohne Harness.
- Keine personenbezogenen Entscheidungen.
- Keine Cloud-Abhaengigkeit.

**Kurz:** Die Security AI ist die **kontrollierte
Ausfuehrungsumgebung** und der **zentrale Hub**. Sie
entscheidet nichts ueber Menschen. Sie fuehrt aus, was
der Mensch freigegeben hat.

### 2.3 Kunden-Mitarbeiter-KI (Ebene 3 — Kunde)

Die Kunden-Mitarbeiter-KI ist die **KI fuer die
Mitarbeiter des Kunden**. Sie ist die Schnittstelle
zwischen Mensch und Daten.

**Was sie macht:**

1. **Fragen entgegennehmen.** Jeder Mitarbeiter fragt
   in natuerlicher Sprache ("Wie viele Urlaubstage
   habe ich?", "Zeig mir Urlaub von Mueller.",
   "Trage Urlaub 01.10.-05.10. ein.").

2. **Kontext verstehen.** Sie kennt den Principal
   (wer fragt), die Rolle, die Berechtigungen.

3. **An Security AI weiterleiten.** Jede Anfrage geht
   an die Security AI. Die entscheidet, was erlaubt ist.

4. **Antworten formulieren.** Sie formuliert die
   Antwort in natuerlicher Sprache.

5. **Schreibaktionen vorschlagen.** Sie schlaegt
   Change Requests vor ("Trage Urlaub ein"). Der Mensch
   gibt frei.

**Was sie NICHT macht:**

- Kein direkter Datenzugriff. Alles ueber Security AI.
- Keine Aktionen ohne Approval.
- Keine Entscheidungen ueber Personen.
- Keine Umgehung der Security AI.

**Kurz:** Die Kunden-Mitarbeiter-KI ist der **Assistent
des Endkunden**. Sie ist die einzige KI, mit der
Endkunden-Mitarbeiter direkt sprechen.

## 3. Die Bridges — die Cloud-Anbindungen

Die Bridges sind **Adapter zu Cloud-Systemen**. Sie
laufen **unter** der Security AI. Sie werden von ihr
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

- Direkt auf Daten zugreifen (nur ueber Security AI).
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

    Security AI (prueft)
      -> Bridge (verbindet)
        -> Externes System (liefert Daten)
      <- Bridge (mappt)
    <- Security AI (auditiert, antwortet)

## 4. Wie die drei Ebenen zusammenspielen

### Beispiel 1 — Kunden-Mitarbeiter fragt

    Mitarbeiter (Buchhaltung):
      "Zeig mir Urlaub von Mueller."

    Kunden-Mitarbeiter-KI:
      - Versteht die Frage
      - Leitet an Security AI weiter

    Security AI:
      - Prueft RBAC: Rolle "buchhaltung" -> darf HR lesen?
      - Prueft Daten-Level: Urlaub = Level 2
      - Ergebnis: JA
      - Waehlt Bridge: HR-Bridge (Personio)
      - Ruft Bridge auf
      - Bridge holt Daten: "Mueller, 12 Tage uebrig"
      - Audit-Eintrag
      - Antwort an Mitarbeiter-KI

    Kunden-Mitarbeiter-KI:
      "Mueller hat 12 Tage uebrig."

### Beispiel 2 — Kunden-Mitarbeiter weist an

    Mitarbeiter (Buchhaltung):
      "Trage ihm Urlaub vom 01.10. bis 05.10. ein."

    Kunden-Mitarbeiter-KI:
      - Versteht: Schreibaktion
      - Leitet an Security AI weiter

    Security AI:
      - Prueft RBAC: Rolle "buchhaltung" -> darf schreiben?
      - Ergebnis: JA (mit Approval)
      - Erstellt Change Request
      - Legt in Approval Queue
      - Wartet

    Human Admin (Mensch):
      - Sieht Change Request
      - Prueft Datum, Person
      - Gibt frei

    Security AI:
      - Ruft HR-Bridge auf
      - Bridge schreibt: "Urlaub 01.10.-05.10. fuer Mueller"
      - Audit-Eintrag
      - Antwort an Mitarbeiter-KI

### Beispiel 3 — Mitarbeiter fragt eigene Daten

    Mitarbeiter:
      "Wie viele Urlaubstage habe ich?"

    Kunden-Mitarbeiter-KI:
      - Versteht: eigene Daten
      - Leitet an Security AI weiter

    Security AI:
      - Prueft Principal: max.mustermann
      - Sonderfall "self": nur eigene Daten
      - Ergebnis: JA
      - Ruft HR-Bridge auf
      - Antwort: "Du hast 8 Tage uebrig."

### Beispiel 4 — IT Firma fragt Kunden-Status

    IT Firma (Admin):
      "Zeig mir alle Kunden mit kritischen Events."

    Security Master AI:
      - Versteht: Aggregat ueber alle Kunden
      - Fragt jede Security AI: "Kritische Events?"
      - Security AI: prueft, antwortet aggregiert
      - Antwort: "3 Kunden mit kritischen Events."
      - KEIN Zugriff auf einzelne Personen.

## 5. Die Reise in einem Satz

Wir bauen ein System, das heute ein Homelab-Netzwerk
ueberwacht, morgen mehrere Firmenstandorte foederiert
und uebermorgen eine KI-Schicht ueber allen relevanten
Firmendaten bildet — mit digitalen UND physischen
Zugriffen, mit Human-in-the-Loop, mit lueckenlosem
Audit und DSGVO-konform.

Der Mensch entscheidet. Die Security Master AI
verwaltet und koordiniert. Die Security AI kontrolliert
und fuehrt aus. Die Kunden-Mitarbeiter-KI assistiert
dem Endnutzer. Jede Aktion ist auditierbar und
umkehrbar.

## 6. Kurzbeschreibung

Das System erkennt unbekannte Geraete, Gast-WLAN-
Aktivitaet, Port-Scans und Web-Reconnaissance in einem
Netzwerk. Es erfasst physische Zutrittsereignisse
(RFID, Magnetkarte, PIN, optional Biometrie), bewertet
sie deterministisch, alarmiert per Telegram und legt
die Daten als Grundlage fuer eine spaetere
KI-gestuetzte Analyse aus.

Besonders wichtig: Das System korreliert **digitale
und physische Sicherheit**. Es erkennt Zusammenhaenge,
die einzelne Systeme niemals sehen wuerden.

Das Projekt ist bewusst als kleine, lauffaehige
Referenz angelegt — mit der Architektur, die spaeter
auf mehrere Netzwerke, Gebaeude und Unternehmens-
umgebungen skaliert werden kann.

## 7. Grundprinzipien

1. **Mensch behaelt Kontrolle.** Kritische Entscheidungen
   sind immer Human-Approval-pflichtig.
2. **Defense in Depth.** Mehrere Schichten.
3. **Determinismus wo moeglich, KI nur wo noetig.**
   Detection ist regelbasiert. Das LLM erklaert, plant
   und schlaegt vor — es bewertet nicht.
4. **Autarkie.** Jede lokale Security AI funktioniert
   ohne die Security Master AI.
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
12. **Ein zentraler Hub.** Die Security AI ist die
    einzige Schnittstelle zu allen Bridges. Nichts
    laeuft an ihr vorbei.

## 8. Skalierungspfad

### Stufe 1 — Netzwerk Homelab (heute)
Ein Netzwerk. Eine Security AI. Keine Security
Master AI. Keine Kunden-Mitarbeiter-KI.
Status (2026-09-26): [x] implementiert (Commit f986ba2).

### Stufe 2 — Erweiterung (Monate)
Change-Request-Generator. Approval-Queue. Lokales LLM.
Status (2026-09-26): [x] implementiert (Commit f986ba2).

### Stufe 2.5 — Lokale KI (Monate)
Ollama, Chat, RBAC, Auto-Switch.
Status (2026-09-26): [x] implementiert (Commit f986ba2).

### Stufe 3 — Foederation (spaeter)
Mehrere isolierte Netzwerke. Zentrale Security
Master AI (Cloud). MCP-Protokoll.
Pro Netzwerk eigene Credentials, eigene Policies.

### Stufe 4 — Enterprise (Zukunft)
Drei Themen, die zusammengehoeren:

**Enterprise-Bridges.**
Die Security AI wird zur zentralen Schnittstelle
fuer alle Cloud-Systeme des Kunden (HR, Buchhaltung,
CRM, Tickets, M365, LLMs). Jede Bridge ist ein
Adapter. Nichts laeuft an der Security AI vorbei.

**Kunden-Mitarbeiter-KI.**
Die KI fuer die Mitarbeiter des Kunden. Jeder
Mitarbeiter fragt in natuerlicher Sprache. Die KI
liest Daten ueber die Security AI, schlaegt
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

Die Security Master AI und die Security AI sprechen
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
- Ein zentraler Hub: Die Security AI ist die einzige
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
  die fuer sie relevanten Daten gibt — in
  natuerlicher Sprache, ueber die Kunden-
  Mitarbeiter-KI.
- Personalverwaltung, HR-Daten, Buchhaltung und
  Sicherheit zusammenfuehrt — mit strikter
  RBAC-Kontrolle und DSGVO-Konformitaet.
- An externe Cloud-KIs ueber offizielle Protokolle
  angebunden werden kann (MCP) — oder autark lokal
  laeuft, wenn Cloud nicht gewuenscht ist.
- Jede Aktion auditiert, jede Entscheidung
  menschlich freigegeben, jede Aenderung umkehrbar.

Drei KI-Ebenen. Klar getrennt. Jede mit eigener
Rolle. Die Security Master AI verwaltet die Kunden
der IT Fabrik. Die Security AI ist der zentrale
Kontrollpunkt beim Kunden — die einzige Schnittstelle
zu allen Bridges. Die Kunden-Mitarbeiter-KI
assistiert den Endnutzer.

Der Mensch bleibt immer die letzte Instanz.

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

