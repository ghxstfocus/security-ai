# Homelab Security AI — Projekt-Vision

> Ein modulares, defensives Security- und Admin-System für
> autorisierte IT- und Gebäudeumgebungen. Referenz-Implementierung
> einer föderierten, KI-gestützten Sicherheitsarchitektur mit
> strikter Human-in-the-Loop-Kontrolle.

## 1. Kurzbeschreibung

Das System erkennt unbekannte Geräte, Gast-WLAN-Aktivität,
Port-Scans und Web-Reconnaissance in einem Netzwerk. Es erfasst
physische Zutrittsereignisse (RFID, Magnetkarte, PIN, optional
Biometrie), bewertet sie deterministisch, alarmiert per Telegram
und legt die Daten als Grundlage für eine spätere KI-gestützte
Analyse aus.

Besonders wichtig: Das System korreliert **digitale und physische
Sicherheit**. Es erkennt Zusammenhänge, die einzelne Systeme
niemals sehen würden — zum Beispiel, wenn jemand mit niedriger
Zutrittsberechtigung versucht, in einen höher gesicherten Raum
zu gelangen, oder wenn ein digitaler Login auf einem System
erfolgt, zu dessen physischem Raum die Person keinen Zutritt hat.

Das Projekt ist bewusst als kleine, lauffähige Referenz angelegt —
mit der Architektur, die später auf mehrere Netzwerke, Gebäude
und Unternehmensumgebungen skaliert werden kann.

## 2. Übergeordnetes Ziel

Eine **Admin AI** als "Head of Operations" für mehrere voneinander
isolierte Netzwerke und Gebäude. Lokale **Security AIs** liefern
Events (digital und physisch), die Admin AI korreliert, bewertet
und Change Requests vorschlägt. Der Mensch entscheidet. Jede
Aktion ist auditierbar und umkehrbar.

Ziel ist **nicht** autonome KI, sondern **kontrollierte
Augmentation** menschlicher Administratoren und Sicherheits-
Verantwortlicher — mit klaren Grenzen, Guardrails und
nachvollziehbaren Entscheidungen.

### Zwei Betriebsmodi

**Modus A — Autark (heute bis Stufe 2).**
Eine Security AI pro Netzwerk/Gebäude. Lokales LLM für
Erklärungen. Läuft vollständig ohne Cloud. Der Mensch
entscheidet alles. Die Admin AI ist nicht vorhanden.

**Modus B — Föderiert (Stufe 3+).**
Mehrere Security AIs sind über MCP mit einer zentralen
Admin AI verbunden. Die Admin AI koordiniert, korreliert und
schlägt Change Requests vor. Der Mensch entscheidet weiterhin
alles.

Wichtig: **Modus A bleibt immer funktionsfähig.** Die Admin AI
ist optional. Wenn die Cloud ausfällt oder nicht erreichbar ist,
läuft das lokale System weiter.

## 3. Grundprinzipien

1. **Mensch behält Kontrolle.** Kritische Entscheidungen
   (Whitelist, Firewall, Deployments, Zutrittsänderungen) sind
   immer Human-Approval-pflichtig.
2. **Defense in Depth.** Mehrere Schichten. Wenn eine versagt,
   greift die nächste.
3. **Determinismus wo möglich, KI nur wo nötig.** Detection ist
   regelbasiert. Das LLM erklärt, plant und schlägt vor — es
   bewertet nicht.
4. **Autarkie.** Jede lokale Security AI funktioniert ohne die
   Admin AI. Die Admin AI verstärkt, aber sie ist keine
   Voraussetzung.
5. **Eine Quelle der Wahrheit.** Policies, Whitelist, Events —
   je genau ein Ort.
6. **Append-only Audit.** Jede Aktion unveränderlich
   protokolliert.
7. **Fail closed.** Wenn ein Guardrail nicht prüfen kann,
   blockiert er.
8. **Keine Cloud-Abhängigkeit im Kern.** Lokale Modelle, lokale
   Daten. Cloud nur als optionale Verstärkung.
9. **Föderation statt Monolith.** Jedes Netzwerk/Gebäude
   eigenständig, die Admin AI optional.
10. **Physisch-digital vereint.** Zutritt und Netzwerkzugriff
    werden gemeinsam betrachtet, nicht getrennt.

## 4. Die drei KI-Rollen

Das System kennt drei Rollen. Jede hat klar definierte Rechte
und Grenzen.

### 4.1 Human Admin (der Mensch)

**Wer:** Du, oder später Sicherheitsverantwortliche in Firmen.

**Was er tut:**
- Whitelist pflegen
- Change Requests freigeben oder ablehnen
- Policies anpassen
- Zutrittsberechtigungen anpassen
- Notfall-Stop
- Letzte Instanz bei kritischen Entscheidungen

**Was er NICHT tut:**
- Er muss nicht jeden Alarm selbst prüfen — das System
  priorisiert und erklärt.
- Er muss nicht alles selbst administrieren — die Admin AI
  schlägt vor.

**Letzte Instanz:** Immer. Keine KI darf eine kritische
Entscheidung ohne ihn treffen.

### 4.2 Security AI (lokal, pro Netzwerk und Gebäude)

**Wer:** Eine eigene Instanz pro Netzwerk und Gebäude. Läuft im
Container. Kann autark betrieben werden (Modus A).

**Was sie tut:**
- Empfängt Events von Sensoren (Netzwerk, RFID, Türen, Logs)
- Wendet deterministische Detection-Regeln an
- Berechnet Risk-Scores
- Sendet Alarme (Telegram) bei Sicherheitsvorfällen
- Loggt alles in die Datenbank
- Bietet ein Dashboard mit Chat-Funktion für Erklärungen
- Kann Change Requests vorbereiten
- Nutzt lokales LLM (z. B. Qwen, Llama) für Erklärungen

**Was sie NICHT tut:**
- Keine direkten Systemänderungen
- Keine Whitelist-Änderungen
- Keine Policies ändern
- Kein Zugriff ausserhalb autorisierter Bereiche
- Keine Scans ohne Harness

**Modell:** Lokal (Ollama). Reicht für Erklärungen und Kontext.

### 4.3 Admin AI (Cloud, Head of Operations)

**Wer:** Eine eigene Instanz, an die Security AIs angekoppelt.
Nicht Teil des lokalen Systems, sondern ein separater Dienst.

**Was sie tut:**
- Events aus mehreren Netzwerken und Gebäuden korrelieren
- Muster über Standorte hinweg erkennen
- Change Requests generieren (Code, Exploits, Policies)
- Code schreiben, Tests vorschlagen, Rollbacks vorbereiten
- Über MCP mit externen LLMs sprechen (Anthropic, OpenAI,
  DeepSeek)
- Reports erstellen

**Was sie NICHT tut:**
- Keinen direkten Produktionszugriff
- Keine Whitelist-Änderungen
- Keine autonomen Deployments
- Keine Aktion ohne Human Approval (ab Level 4)
- Kein Zugriff auf Rohdaten der Netzwerke — nur Events

**Modell:** DeepSeek (in diesem Projekt), alternativ andere
Cloud-LLMs. Später: Kopplung an externe KIs von Firmen
(Anthropic, OpenAI) über MCP.

**Wichtig:** Die Admin AI ist optional. Modus A (autark) bleibt
immer funktionsfähig. Die Admin AI verstärkt, sie ist keine
Voraussetzung.

## 5. Architektur (4-Ebenen-Modell)

Der Datenfluss geht **aufwärts** (Events, Beobachtungen) und
**abwärts** (Change Requests, Entscheidungen). Keine Ebene
überspringt eine andere.

## 6. Skalierungspfad (6 Stufen)

### Stufe 1 — Netzwerk Homelab (heute)
Ein Netzwerk. Eine Security AI. Keine Admin AI.
Deterministische Detection. Lokales LLM für Erklärungen.
Telegram-Alarme. SQLite-Datenbank.

### Stufe 2 — Erweiterung (Monate)
Change-Request-Generator. Human-in-the-Loop mit Approval-Queue.
Lokales LLM wird für Kontext und Erklärungen genutzt.
Der Mensch arbeitet mit dem System, nicht nur daneben.

### Stufe 3 — Föderation (später)
Mehrere isolierte Netzwerke. Zentrale Admin AI (Cloud).
Standardisiertes Protokoll (MCP-basiert).
Pro Netzwerk eigene Credentials, eigene Policies.
Die Admin AI korreliert Events über Netzwerke hinweg.

### Stufe 4 — Enterprise-Bridges (Zukunft)
Anbindung an externe LLMs (Anthropic, OpenAI, DeepSeek).
Standardisierte Schnittstellen für Unternehmen.
Firmen können ihre eigene KI anbinden.
Zertifizierungen (ISO 27001, SOC 2) als Ziel.

### Stufe 5 — Physische Sicherheit
Gebäudesicherheit als eigene Schicht:
- Raum-Sicherheitslevel (0-5, unabhängig von Tool-Level)
- Zutrittstechnologien: RFID, Magnetkarte, PIN, optional Biometrie
- Türen, Leser, Sensoren als Event-Quellen
- Personen als eigene Entitäten mit Raum- und Tool-Level

Die Security AI erfasst Zutrittsereignisse, die Detection Engine
wendet physische Regeln an, die Admin AI korreliert mit digitalen
Events.

### Stufe 6 — Ganzheitliche Korrelation
Die eigentliche Königsklasse: digitale und physische Sicherheit
sind **verheiratet**. Die Admin AI erkennt Zusammenhänge, die
einzelne Systeme niemals sehen würden.

Beispiele:
- Person mit Raum-Level 2 versucht, einen Raum mit Level 4 zu
  betreten -> Alarm
- Person betritt einen Raum nicht, obwohl sie digital auf ein
  System in diesem Raum zugreift -> verdächtig
- Person verlässt einen Raum, digitaler Zugriff bleibt aktiv ->
  Alarm
- Person loggt sich in einen Server ein, der in einem Raum steht,
  zu dem sie keinen Zutritt hat -> kritischer Alarm
- Person versucht nachts um 3 Uhr Zutritt, obwohl sie tagsüber
  nie im Gebäude ist -> Anomalie
- Zugang außerhalb der Arbeitszeit -> Alarm je nach Raum-Level

Diese Korrelation ist der eigentliche Mehrwert gegenüber
Einzelsystemen. Sie ist der Grund, warum die Architektur so
gebaut ist, wie sie ist.

## 7. Physische Sicherheit (Stufe 5)

### 7.1 Raum-Sicherheitslevel (0-5)

Analog zur Tool-Level-Skala, aber **unabhängig**. Eine Person
mit Tool-Level 4 hat nicht automatisch Raum-Level 4.

| Level | Bedeutung         | Beispiel                    |
|-------|-------------------|-----------------------------|
| 0     | Öffentlich        | Empfang, Flure              |
| 1     | Niedrig           | Besucherbereiche            |
| 2     | Normal            | Büros, Mitarbeiterbereiche  |
| 3     | Erhöht            | IT, Management              |
| 4     | Hoch              | Serverraum, Tresor          |
| 5     | Kritisch          | Sicherheitszentrale, Vorstand |

### 7.2 Zutrittstechnologien

Das Gebäudemodul ist **flexibel**. Es unterstützt:

- **RFID** (Mifare, HID, Legic, ...)
- **Magnetkarte**
- **PIN**
- **Biometrie** (optional, nur mit ausdrücklicher Zustimmung)

Weitere Technologien sind über ein Plugin-System ergänzbar.
Jede Technologie liefert Events im **gleichen Schema** — die
Detection Engine und die Admin AI müssen nichts über die
Technologie wissen.

### 7.3 Personen als Entitäten

Personen sind eigene Entitäten in der Datenbank. Sie haben:

- Eine eindeutige ID
- Einen Namen
- Einen Typ (Mitarbeiter, Dienstleister, Besucher, ...)
- **Raum-Level** (welche Räume darf die Person betreten?)
- **Tool-Level** (auf welche Systeme darf sie zugreifen?)
- Zeitliche Einschränkungen (Arbeitszeiten)
- Optional: Zutrittshistorie (mit Aufbewahrungsfrist)

### 7.4 Korrelationsregeln

Die Detection Engine kennt Regeln, die **digital und physisch**
verknüpfen:

- **access_level_mismatch:** Person mit Raum-Level < Raum-Level
  versucht Zutritt
- **access_outside_hours:** Zutritt außerhalb der erlaubten Zeiten
- **digital_without_physical:** Digitaler Login auf System in
  Raum, zu dem die Person keinen Zutritt hat
- **physical_without_digital:** Person betritt Raum, in dem ein
  aktiver digitaler Zugriff mit ihrer ID läuft, den sie nicht
  gestartet hat
- **access_after_departure:** Digitaler Zugriff bleibt aktiv,
  nachdem die Person den Raum verlassen hat
- **unusual_pattern:** Zutrittsmuster weicht von der Historie ab
- **tailgating:** Zwei Personen betreten einen Raum mit einer
  Karte (falls Sensorik verfügbar)

### 7.5 Ethische Leitplanken (verbindlich)

Physische Sicherheit ist sensibel. Die folgenden Regeln sind
**verbindlich** — sie sind Teil der Architektur, nicht optional:

- **Keine Gesichtserkennung** ohne ausdrückliche schriftliche
  Freigabe der betroffenen Personen.
- **Keine biometrischen Daten** ohne ausdrückliche Zustimmung.
  Biometrie ist optional und nie Standard.
- **Keine Bewegungsprofile** einzelner Personen. Nur
  Zutritts-Events, keine Positionen im Raum.
- **Keine dauerhafte Speicherung** von Zutrittsdaten ohne
  definierten Zweck und Aufbewahrungsfrist.
- **Transparenz:** Betroffene Personen haben ein Recht zu
  wissen, welche Daten erfasst werden.
- **Zweckbindung:** Daten werden nur für Sicherheitszwecke
  verwendet, nie für Leistungsbewertung oder andere Zwecke.
- **Löschfristen:** Zutrittsdaten werden nach definierter Frist
  gelöscht, außer bei dokumentierten Vorfällen.
- **Zugriffskontrolle:** Nur autorisierte Personen können
  Zutrittsdaten einsehen. Jeder Zugriff wird auditiert.

Diese Leitplanken sind **nicht nur ethisch**, sondern auch
**rechtlich** erforderlich (DSGVO und vergleichbare Regelungen).
Ein System ohne diese Leitplanken ist in vielen Ländern nicht
einsatzfähig.

## 8. MCP-Kopplung an externe LLMs

Die Admin AI spricht über **MCP** (Model Context Protocol) mit
externen LLMs. Das erlaubt:

- Wahl des Modells pro Aufgabe (DeepSeek, Anthropic, OpenAI)
- Anbindung durch Firmen an ihre eigene KI
- Wechsel ohne Neuentwicklung des Systems
- Kostenoptimierung

Die Admin AI selbst kann mit mehreren externen LLMs
kommunizieren. Sie fungiert als **Vermittler** zwischen dem
lokalen Sicherheitssystem und der KI-Landschaft.

Beispiel: Eine Firma nutzt bereits Anthropic Claude. Sie will
ihre Admin AI mit Claude statt mit DeepSeek betreiben. Das ist
möglich, weil die Schnittstelle MCP-basiert und standardisiert
ist.

Die lokalen Security AIs müssen **nichts** davon wissen. Sie
liefern Events an die Admin AI. Wie die Admin AI diese
verarbeitet, ist ihre Sache.

## 9. Datenmodell (heute und Ziel)

### 9.1 Heute (Stufe 1)

SQLite-Datenbank (`homelab.db`):

- `whitelisted_devices` — manuell gepflegte Whitelist
- `device_logins` — lückenloses Log aller gesehenen Geräte
- `security_alerts` — Vorfälle (unknown_device, guest_device,
  port_scan, http_recon)
- `system_history` — Infrastruktur-Snapshots
- `error_logs` — Fehler

### 9.2 Ziel (Stufe 5+)

Erweitert um:

- `persons` — Personen als Entitäten
- `rooms` — Räume mit Sicherheitslevel
- `access_events` — Zutrittsereignisse
- `access_permissions` — Wer darf wohin
- `tool_permissions` — Wer darf auf welches System
- `correlations` — Verknüpfungen digital/physisch

### 9.3 Events sind einheitlich

Alle Events — egal ob digital oder physisch — nutzen das
gleiche Schema:

    Event(
        event_id="EVT-2026-09-20-abc12345",
        timestamp=...,
        source="fritzbox" | "rfid_reader_01" | "docker",
        event_type="unknown_device" | "access_attempt",
        severity=Severity.WARNING,
        data={...},
        network_id="homelab-ct101",
    )

Das erlaubt der Detection Engine und der Admin AI, **ohne
Unterschied** mit digitalen und physischen Events zu arbeiten.

## 10. Alarm-Regeln

### 10.1 Digital

| Ereignis                              | Telegram | DB  |
|---------------------------------------|----------|-----|
| Gastgerät im Gastnetz                 | nein     | ja  |
| Bekanntes Gerät im Hauptnetz          | nein     | ja  |
| Unbekanntes Gerät im Hauptnetz        | ja (W)   | ja  |
| Whitelist-Gerät macht Port-Scan       | ja (C)   | ja  |
| Externe IP macht Port-Scan            | ja (C)   | ja  |
| HTTP-Recon (nmap-UA, verd. Pfad, 404) | ja (W)   | ja  |

### 10.2 Physisch

| Ereignis                              | Telegram | DB  |
|---------------------------------------|----------|-----|
| Zutritt erfolgreich (erlaubt)         | nein     | ja  |
| Zutritt verweigert (Karte falsch)     | ja (W)   | ja  |
| Raum-Level-Mismatch                   | ja (C)   | ja  |
| Zutritt außerhalb der Arbeitszeit     | ja (W)   | ja  |
| Tailgating erkannt                    | ja (W)   | ja  |
| Tür länger offen als erlaubt          | ja (W)   | ja  |

### 10.3 Korreliert (digital + physisch)

| Ereignis                                       | Telegram | DB  |
|------------------------------------------------|----------|-----|
| Digitaler Login ohne physischen Zutritt        | ja (C)   | ja  |
| Zugriff bleibt aktiv nach Verlassen des Raums  | ja (W)   | ja  |
| Ungewöhnliches Zutrittsmuster                  | ja (W)   | ja  |
| Person verlässt Gebäude, System bleibt offen   | ja (W)   | ja  |
| Mehrere Zutrittsversuche mit niedrigerem Level | ja (C)   | ja  |

W = WARNING, C = CRITICAL

## 11. Security-Prinzipien

- **Whitelist** ist manuell und Mensch-only. Kein Auto-Add, kein
  LLM-Schreibzugriff.
- **Capabilities** werden im Security-Container entzogen. Tools
  laufen in separaten, isolierten Containern.
- **Guardrails** sind Code, nicht Prompt. Sie sind nicht durch
  das Modell überschreibbar.
- **Audit-Logs** sind append-only JSONL, unveränderlich.
- **Keine Shell-Ausführung** durch das Modell. Nur über die Tool
  Registry und die Sandbox.
- **Prompt-Injection** wird im Policy-Layer geblockt.
- **Human-in-the-Loop** ist Pflicht bei Risiko-Level >= 2.
- **Physische Sicherheit** unterliegt denselben Prinzipien wie
  digitale. Kein LLM-Zugriff auf Zutrittsberechtigungen ohne
  Human Approval.

## 12. Nicht-Ziele

- Kein automatisches Blocken von IPs oder Personen ohne Freigabe.
- Kein LLM-Schreibzugriff auf Policies, Whitelist, Guardrails
  oder Zutrittsberechtigungen.
- Keine Cloud-Abhängigkeit im Kern.
- Kein autonomer Deploy in Produktion.
- Keine Fremdsystem-Scans außerhalb autorisierter Bereiche.
- **Keine Gesichtserkennung** ohne ausdrückliche Freigabe.
- **Keine Bewegungsprofile** von Personen.
- **Keine biometrischen Daten** ohne Zustimmung.
- **Keine Zweckentfremdung** von Zutrittsdaten (z. B. für
  Leistungsbewertung).

## 13. Warum dieses Projekt

Ich habe jahrelang nichts mit IT oder Coden zu tun gehabt. Nach
einer Pause habe ich einen Proxmox-Server aufgesetzt, einen
Container erstellt — und gemerkt, dass ich ein System bauen
möchte, das ich selbst im Alltag brauchen kann.

Der Anlass war praktisch: Ich wollte wissen, wer sich in meinem
Netzwerk befindet, und ich wollte Alarme, wenn etwas
Verdächtiges passiert. Aus dieser praktischen Notwendigkeit ist
eine Architektur entstanden, die weit über ein Homelab-Tool
hinausgeht.

Ich glaube, dass KI-gestützte Sicherheit mit Human-in-the-Loop
die Zukunft ist — nicht autonome KI, sondern **verstärkte
menschliche Entscheidungen**. Dieses Projekt ist mein Versuch,
die Referenz für so ein System zu bauen: klein genug, um es zu
verstehen, sauber genug, um es zu erweitern.

## 14. Referenzen

- Architektur: `docs/ARCHITECTURE.md`
- Sicherheit: `docs/SECURITY.md`
- Protokoll: `docs/PROTOCOL.md`
- Berechtigungen: `docs/PERMISSIONS.md`
- Deployment: `docs/DEPLOYMENT.md`

---
Letzte Aktualisierung: 2026-09-21
