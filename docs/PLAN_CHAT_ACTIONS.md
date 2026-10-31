# Plan: Chat als Aktions-Schnittstelle

Status: **Planung** — kein Code, keine Migration, keine Tests.

## 1. Problem

Der Chat ist heute reine Frage-Antwort-Schnittstelle. Es fehlt ein dokumentiertes Konzept, wie der Chat sicher zu einer Aktions-Schnittstelle erweitert werden kann, ohne dass das Modell selbst Aktionen ausfuehrt.

Es gibt keine Planungsdatei, die Zielbild, geplante API-Oberflaeche, RBAC-Permissions, Audit-Pflichten, Abgrenzungen und Akzeptanzkriterien zusammenhaelt.

## 2. Zielbild

Der Chat soll Vorschlaege fuer Aktionen erzeugen koennen, die ein Mensch explizit freigibt. Das Modell fuehrt **niemals** selbst Aktionen aus. Es formuliert lediglich einen strukturierten Vorschlag (Proposal), der ueber einen separaten, kontrollierten Pfad ausgefuehrt wird.

Kernprinzipien:

- **Human-in-the-loop:** Jede Aktion erfordert eine explizite Freigabe durch einen berechtigten Nutzer.
- **Vorschau-Pflicht:** Vor jeder Ausfuehrung muss dem freigebenden Nutzer eine Vorschau der vorgeschlagenen Aktion (Tool, Argumente, erwartete Wirkung) angezeigt werden. Ohne Vorschau keine Freigabe.
- **Trennung von Vorschlag und Ausfuehrung:** Das Modell schlaegt vor, der Ausfuehrungspfad fuehrt aus.
- **Nachvollziehbarkeit:** Jede Ausfuehrung wird auditiert.
- **Least Privilege:** Ausfuehrung nur mit den Rechten des freigebenden Nutzers.

## 3. Abgrenzung: real existierend vs. geplant

Diese Unterscheidung ist verbindlich. Spaetere Implementierungen duerfen **nicht** auf erfundene APIs bauen.

### 3.1 Real im Code-Index vorhanden

- **Audit-Schreibpfad:** Es existiert ein Schreibpfad fuer Audit-Eintraege, ueber den Aktionen revisionssicher protokolliert werden koennen.
- **Approval-Semantik:** Es existiert eine Semantik fuer Freigaben (Approval), die den Zustand einer vorgeschlagenen Aktion abbildet.
- **Tool-Registry:** Es existiert eine Registry, in der ausfuehrbare Tools/Aktionen registriert sind.

### 3.2 Nur geplant (existiert NICHT im Code)

- **ChatService:** Ein Dienst, der Chat-Anfragen verarbeitet und Proposals erzeugt, ist nur geplant.
- **Permissions:** RBAC-Permissions fuer Chat-Aktionen sind nur geplant.
- **Event-Typen:** Spezifische Event-Typen fuer Proposal-Erstellung, Freigabe und Ausfuehrung sind nur geplant.
- **proposal_id:** Eine persistente Kennung fuer Proposals ist nur geplant.

Alle in Abschnitt 4 genannten APIs sind **geplant** und nicht im Code-Index vorhanden.

## 4. Geplante API-Oberflaeche

> Hinweis: Die folgenden Signaturen sind Planungsskizzen, keine existierenden APIs.

- `ChatService.propose_action(principal, vorgeschlagene_aktion, grund) -> Proposal`
  Erzeugt aus einer Chat-Nachricht einen strukturierten Aktionsvorschlag.
  Parameter:
  - `principal` — der anfragende Nutzer (Identitaet fuer RBAC und Audit).
  - `vorgeschlagene_aktion` — die vorgeschlagene Aktion (Tool-Name und Argumente).
  - `grund` — die Begruendung des Vorschlags (wird auditiert).
- `ChatService.list_proposals(...) -> list[Proposal]`
  Listet offene und abgeschlossene Proposals eines Nutzers.
- `ChatService.approve_proposal(proposal_id, ...) -> ApprovalResult`
  Gibt ein Proposal frei und stoesst die Ausfuehrung ueber den kontrollierten Pfad an.
- `ChatService.reject_proposal(proposal_id, ...) -> ApprovalResult`
  Lehnt ein Proposal ab.

Ein `Proposal` enthaelt mindestens: `proposal_id`, `tool_name`, `arguments`, `status`, `created_by`, `created_at`.

## 5. RBAC-Permissions (geplant)

> Hinweis: Diese Permissions existieren nicht im Code-Index.

- `chat.action.propose` — Proposal erzeugen.
- `chat.action.execute` — freigegebenes Proposal ueber den kontrollierten Pfad ausfuehren.
- `chat.action.approve` — Proposal freigeben.
- `chat.action.reject` — Proposal ablehnen.
- `chat.action.list` — eigene Proposals einsehen.

Regeln:

- Ausfuehrung erfolgt ausschliesslich mit den Rechten des freigebenden Nutzers.
- Ein Nutzer darf nur Proposals freigeben, fuer deren Tool er die Ausfuehrungsberechtigung besitzt.
- Proposals sind standardmaessig nur fuer Ersteller und Freigabeberechtigte sichtbar.

## 6. Audit-Pflichten

Jede Zustandsaenderung eines Proposals wird ueber den bestehenden Audit-Schreibpfad protokolliert. Die Audit-Pflicht umfasst mindestens die Event-Typen `chat_action_proposed` und `chat_action_denied`:

- `chat_action_proposed` — Erstellung eines Proposals (wer, welches Tool, welche Argumente, Grund). Enthaelt `proposal_id`.
- `chat_action_denied` — Ablehnung eines Proposals (wer, wann, welches Proposal, optional Begruendung). Enthaelt `proposal_id`.
- Freigabe (wer, wann, welches Proposal).
- Ausfuehrung (Ergebnis, Fehler, Dauer).

Audit-Eintraege sind unveraenderlich und enthalten mindestens: `proposal_id`, `actor`, `action`, `timestamp`, `outcome`.

## 7. Abgrenzungen

- Das Modell fuehrt **keine** Aktionen aus; es erzeugt nur Proposals.
- Kein automatisches Ausfuehren ohne explizite Freigabe.
- Keine Umgehung der Tool-Registry: ausfuehrbar sind nur registrierte Tools.
- Keine Umgehung des Audit-Schreibpfads.
- Diese Datei enthaelt keinen Code, keine Migration und keine Tests.
- Die Migrationsnummer `0019` bleibt unberuehrt, da keine Migration angelegt wird.

## 8. Akzeptanzkriterien

- Ein Chat-Nutzer kann ein Proposal erzeugen, ohne dass eine Aktion ausgefuehrt wird.
- Ein berechtigter Nutzer kann ein Proposal freigeben; erst dann wird die Aktion ueber den kontrollierten Pfad ausgefuehrt.
- Jede Freigabe, Ablehnung und Ausfuehrung erzeugt einen Audit-Eintrag ueber den bestehenden Audit-Schreibpfad.
- Nicht registrierte Tools koennen nicht ausgefuehrt werden.
- Fehlende Permissions verhindern Erzeugung, Freigabe und Ablehnung.
- Die Planungsdatei unterscheidet explizit zwischen real existierenden Bausteinen (Audit-Schreibpfad, Approval-Semantik, Tool-Registry) und geplanten Bausteinen (ChatService, Permissions, Event-Typen, proposal_id).

## 9. Test-Skizzen

> Hinweis: Diese Skizzen beschreiben geplante Tests. Es wird in dieser Phase kein Testcode angelegt.

- **Proposal erzeugen ohne Ausfuehrung:** `propose_action(principal, vorgeschlagene_aktion, grund)` erzeugt ein Proposal mit `status=proposed`; es wird keine Aktion ausgefuehrt; Audit-Event `chat_action_proposed` mit `proposal_id` wird geschrieben.
- **Freigabe fuehrt aus:** `approve_proposal(proposal_id, ...)` durch berechtigten Nutzer fuehrt die Aktion ueber den kontrollierten Pfad aus; Audit-Eintrag fuer Freigabe und Ausfuehrung.
- **Ablehnung:** `reject_proposal(proposal_id, ...)` setzt `status=rejected`; Audit-Event `chat_action_denied` mit `proposal_id`.
- **Fehlende Permission:** Ohne `chat.action.propose` schlaegt `propose_action` fehl; ohne `chat.action.execute` schlaegt die Ausfuehrung fehl.
- **Nicht registriertes Tool:** Ein Proposal mit nicht registriertem Tool kann nicht ausgefuehrt werden.
- **Vorschau-Pflicht:** Ohne angezeigte Vorschau ist keine Freigabe moeglich.
