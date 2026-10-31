# ADR-0025: Admin-AI-Scope

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §25

---

## 25. Admin-AI-Scope

Die Admin AI ist Pflicht fuer die Nutzung des
Systems als Sicherheitssystem. Sie ist nicht
optional.

Sie darf:
- den Core verwalten (lesen, Endpunkte
  registrieren, Rollen aus existierenden
  Typen anlegen),
- Guardrails lesen,
- Angriffe korrelieren, Massnahmen
  vorschlagen,
- Massnahmen mit Human-Approval ausfuehren,
- die Kunden-KI konfigurieren und ueberwachen,
- Bridges registrieren und verwalten.

Sie darf nicht:
- Guardrails schreiben/aendern,
- Core-Aenderungen ohne Change Request,
- sich selbst privilegieren,
- Core-Admins anlegen,
- ohne Human-Approval kritische Aktionen
  ausfuehren.

Siehe docs/ADMIN_AI_SCOPE.md.
