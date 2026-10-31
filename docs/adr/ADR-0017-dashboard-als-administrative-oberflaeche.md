# ADR-0017: Dashboard als administrative Oberflaeche

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §17

---

## 17. Dashboard als administrative Oberflaeche

Das Dashboard ist nicht nur Anzeige, sondern
Steuerpult. Die Rollenverschiebung ist explizit.

- UI ruft nur Services (bestehende Regel, 11).
- CSP/CSRF/RBAC bleiben unveraendert (16).
- Aktionen werden im Human-in-the-Loop-Schema
  eingeordnet (AUTOMATIC / REVIEW /
  APPROVAL_REQUIRED).
- Kritische Aktionen laufen ausschliesslich als
  Change Request. Kein direkter Ausfuehrungspfad
  im UI.
- Der Bestaetigungsdialog ist die einzige
  Schnittstelle zwischen Bedienung und Wirkung.
  Grund: der Mensch muss vor dem Anlegen die
  Auswirkung und den Rollback sehen.
- Kurze Wege in der Bedienung: Aktionen sitzen
  auf der Detailseite und pro Zeile in Live-Listen,
  nicht in Sammel-Reitern.
- Change Request ist Pflicht bei Level 2+.

Zwei Aufrufwege:

- Level 0-1 read-only: UI -> Service ->
  Werkbank-Registry -> Tool.
- Level 2+: UI -> Service -> AgentLoop ->
  Harness -> Tool.

Der Service entscheidet den Pfad. Kein direkter
Import des Orchestrators im Dashboard.

Ausnahme: Services-Status auf /system (Punkt 66).
Der SystemStatusService ruft systemctl is-active fuer
die drei eigenen security-ai-Units direkt auf
(subprocess.run, shell=False, timeout=2). Das ist die
einzige subprocess-Anwendung aus einem UI-nahen Pfad.
Die Ausnahme ist in WEB_SECURITY_CHECKLIST §N
dokumentiert und eng gefasst.
