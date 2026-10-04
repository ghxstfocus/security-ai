# Admin AI — Scope und Grenzen

> Verbindliche Beschreibung der Rolle der Admin AI.
> Was sie darf, was nicht, wie sie mit dem Core
> spricht, wie sie sich von der Kunden-KI
> unterscheidet.

Stand: 2026-10-04 | HEAD: <wird nach Commit gesetzt>

## 1. Rolle und Zweck

Die Admin AI ist die zentrale Intelligenz- und
Bedienungsschicht des Systems. Sie laeuft in der
Cloud der Firma (typisch Azure in Deutschland).
Sie ist die "rechte Hand" der IT.

Sie ist Pflicht, wenn das System als
Sicherheitssystem genutzt wird. Ohne sie bleibt
der Core ein deterministischer Detektor und
Regelvollstrecker — funktional, aber nicht
das, was das System als Produkt ausmacht.

Sie ist nicht optional im Sinne eines
"nice to have". Sie ist Teil der
Sicherheitsarchitektur.

## 2. Was die Admin AI darf

### 2.1 Core-Verwaltung

- Den Core lesen: Events, Alerts, Risk,
  Inventory, Audit, Approvals, Changes.
- Den Core-Zustand verwalten: Endpunkte
  registrieren, Rollen anlegen (siehe 4),
  Faehigkeiten registrieren.
- Vorschlaege erstellen: Change Requests
  fuer Core-Aenderungen (Policy, Guardrails).
- Den Change Applier ausloesen (mit
  Human-Approval).

### 2.2 Endpunkt-Verwaltung

- Endpunkte registrieren, aktivieren,
  deaktivieren.
- Endpunkt-Agenten aktualisieren (ueber den
  Core).
- Endpunkt-Status ueberwachen (Heartbeat).
- Endpunkt-Faehigkeiten abfragen.

### 2.3 Angriffserkennung und Reaktion

- Angriffsmuster ueber mehrere Endpunkte
  korrelieren.
- Gegenmassnahmen vorschlagen.
- Massnahmen mit Human-Approval ausfuehren:
  - ISOLATE (Netz-Segmentierung).
  - BLOCK (Netz-Zugriff entziehen).
  - KILL (laufende Verbindungen trennen,
    mit Approval).

### 2.4 Rollen-Anlage (siehe 4)

- Neue Rolleninstanzen aus existierenden
  Rollentypen anlegen.
- Rollen zuweisen an Principals.
- Rollen entziehen.

### 2.5 Kunden-KI-Verwaltung

- Kunden-KI konfigurieren.
- Kunden-KI-Berechtigungen setzen (innerhalb
  der Vorgaben).
- Kunden-KI-Aktivitaet ueberwachen.

### 2.6 Bridges

- Bridges registrieren (HR, CRM, Tickets,
  M365, etc.).
- Bridge-Berechtigungen setzen.
- Bridge-Aktivitaet lesen.

## 3. Was die Admin AI nicht darf

### 3.1 Guardrails

- Guardrails lesen: ja.
- Guardrails schreiben/aendern: nein.
- Guardrail-Konfiguration ist Mensch-only
  (ueber Dashboard oder CLI).

### 3.2 Core-Aenderungen

- Policy-Dateien schreiben: nein.
- Core-Schema aendern: nein.
- Migrations ausfuehren: nein.
- Selbst-Updates: nein.

### 3.3 Selbstprivilegierung

- Sich selbst eine Rolle anlegen: nein.
- Sich selbst neue Berechtigungen geben: nein.
- Einen Admin fuer den Core anlegen: nein.
- Den eigenen Scope erweitern: nein.

Der Core-Admin wird vom Menschen angelegt.

### 3.4 Ohne Human-Approval ausfuehren

- Level 2-3 (REVIEW): Bestaetigung vor
  Ausfuehrung.
- Level 4 (APPROVAL): explizite Freigabe.
- Kein Auto-Block ohne Freigabe.
- Kein Auto-KILL.

### 3.5 Direkter System-Zugriff

- Kein direkter Shell-Zugriff.
- Kein direkter Datenbank-Zugriff (immer
  ueber Core-Services).
- Kein direkter Zugriff auf Core-Interna
  (Dateien in policies/, harness/guardrails/).

## 4. Rollentypen und Rolleninstanzen

### 4.1 Rollentypen

Ein Rollentyp ist eine Vorlage. Er definiert:
- einen Namen (z. B. "Buchhalter", "Personaler",
  "IT-Admin", "Sicherheits-Analyst"),
- die Domaenen, in denen der Typ handeln darf
  (Buchhaltung, Personal, IT, Sicherheit),
- die Permissions innerhalb jeder Domaene,
- ob der Typ ein Core-Admin ist (nur Mensch
  darf Core-Admins anlegen).

Rollentypen werden im Core definiert. Sie sind
Bestand der Installation.

### 4.2 Rolleninstanzen

Eine Rolleninstanz ist eine konkrete Rolle, die
einem Principal zugewiesen wird. Sie entsteht
aus einem Rollentyp.

Die Admin AI darf Rolleninstanzen anlegen,
wenn:
- der Rollentyp existiert,
- der Rollentyp kein Core-Admin ist,
- die Zuweisung im Rahmen der Berechtigung
  der Admin AI liegt.

### 4.3 Core-Admin-Ausnahme

Der Core-Admin (die hoechste Rolle) darf nur
vom Menschen angelegt werden. Grund: die
Admin AI darf sich nicht selbst die
Kontrolle ueber den Core geben.

## 5. Wie sie mit dem Core spricht

### 5.1 Authentifizierung

Die Admin AI authentifiziert sich beim Core
ueber gegenseitige Zertifikate (mTLS). Der Core
kennt die Admin AI. Kein Shared Secret.

Jede Firma hat ihre eigene Admin AI. Jede
Admin AI hat ihr eigenes Zertifikat. Der Core
weist es beim ersten Kontakt zu und speichert
den Fingerprint.

### 5.2 Protokoll

Der Core spricht mit der Admin AI ueber ein
definiertes Protokoll. Es definiert:
- Registrierung der Admin AI beim Core.
- Nachrichten-Format (Anfrage, Antwort).
- Signatur aller Nachrichten.
- Nonce und Ablauf (Replay-Schutz).
- Heartbeat (ist die Admin AI erreichbar?).
- Fail closed (kein Auftrag ohne gueltige
  Signatur).

Das Protokoll wird in docs/PROTOCOL_ADMIN_AI.md
(neu, spaeter) spezifiziert.

### 5.3 Audit

Jede Interaktion zwischen Core und Admin AI
wird auditiert:
- Anfrage (Admin AI -> Core).
- Antwort (Core -> Admin AI).
- Vorschlag (Admin AI).
- Approval (Mensch).
- Ausfuehrung (Core/Applier).
- Ergebnis.

Audit-Kinds:
- admin_ai_request
- admin_ai_response
- admin_ai_proposal
- admin_ai_execution

## 6. Datenklassifikation

Jede Information, die durch den Core geht,
hat eine Vertraulichkeitsstufe:

- **Oeffentlich.** Darf an jeden Cloud-Provider.
- **Intern.** Nur an Provider mit AVV
  (Auftragsverarbeitungsvertrag).
- **Vertraulich.** Nur an Provider mit AVV
  und in der EU oder gleichwertig.
- **Streng vertraulich.** Nur lokal oder
  gar nicht. Kein Cloud-Provider.

Die Firma entscheidet pro Installation, welche
Stufe welchen Provider nutzen darf.

Der Core filtert jede Anfrage an die Admin AI
nach dieser Klassifikation. Was nicht raus
darf, geht nicht raus.

## 7. Ausfuehrungspfad

Jede Aktion der Admin AI folgt diesem Pfad:

    Vorschlag (Admin AI)
      -> Bestaetigung (Mensch, im Chat oder
         Dashboard)
      -> Core prueft (RBAC, Policy, Guardrails)
      -> Applier fuehrt aus
      -> Audit (append-only)

Kein Schritt darf uebersprungen werden.
Kein Auto-Block ohne Freigabe.
Kein Auto-KILL.

Bei Basis-Massnahmen (ISOLATE) ist die
Firma-Einstellung entscheidend: automatisch
oder mit Approval. Standard: mit Approval.

## 8. Verhaeltnis zur Kunden-KI

Die Kunden-KI braucht die Admin AI. Sie ist
kein eigenstaendiges System.

- Die Admin AI konfiguriert die Kunden-KI.
- Die Admin AI setzt die Berechtigungen
  (innerhalb der Vorgaben des Cores).
- Die Admin AI ueberwacht die Aktivitaet.
- Ohne Admin AI gibt es keine Kunden-KI.

Die Kunden-KI spricht mit dem Core, nicht mit
der Admin AI. Der Core prueft jede Anfrage.
Die Admin AI ist die Intelligenzschicht der
Kunden-KI, nicht ihr Torwaechter.

## 9. Verhaeltnis zum Dashboard

Das Dashboard ist die Basic-Verwaltung.

- Kein LLM. Kein Chat.
- Fuer Notfaelle: wenn die Admin AI nicht
  erreichbar ist.
- Fuer Guardrail-Aktivierung: nur der Mensch
  darf das.
- Fuer klassische Administration:
  Benutzer, Rollen, Audit, Einstellungen.

Das Dashboard ist die Rueckfallebene. Die
Admin AI ist die Komfortebene. Beide greifen
auf denselben Core zu.

## 10. Nicht-Ziele

Die Admin AI ist bewusst nicht:

- Ein Selbstlaeufer. Sie handelt mit Approval.
- Ein Core-Admin. Sie darf keine Core-
  Aenderungen ohne Change Request.
- Ein Ersatz fuer den Core. Sie ist
  Intelligenzschicht, nicht Fundament.
- Ein Ersatz fuer den Menschen. Sie ist
  rechte Hand, nicht Entscheider.
- Ein Cloud-Zwang. Der Core laeuft auch
  ohne sie.
- Eine Blackbox. Jede Aktion ist auditierbar.

## 11. Verweise

- docs/ARCHITECTURE.md — technische Schichten.
- docs/SECURITY.md — Threat Model.
- docs/DESIGN_DECISIONS.md — Design-Entscheidungen.
- docs/PHASES.md — Phasenplanung (Phase 13).
- docs/PROTOCOL_ADMIN_AI.md (geplant) —
  Protokoll-Spezifikation.
- docs/CONTEXT_PROMPT.md — Einstieg fuer
  neue Sessions.
