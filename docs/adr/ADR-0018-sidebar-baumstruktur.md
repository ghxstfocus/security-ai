# ADR-0018: Sidebar-Baumstruktur

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §18

---

## 18. Sidebar-Baumstruktur

Die Sidebar wird Baum mit Bereichen und
Untermenues:

- Uebersicht
- Inventar (Alle, Aktive, Hauptnetz, Gastnetz,
  Detailseite)
- Alarme (Aktuell, Verlauf, Detail)
- Werkzeuge (Netzwerk-Diagnose, System, Datenbank,
  Audit, Aktionen)
- System-Status
- Verwaltung (Benutzer, Rollen, Guardrails,
  Betriebsparameter, Audit-Log, Einstellungen)

- Untermenues per details/summary oder externem JS
  (CSP-konform, kein Inline-Script).
- Hamburger-Toggle aus 3.6.11 bleibt kompatibel.
