# ADR-0024: Rollentypen und Rolleninstanzen

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §24

---

## 24. Rollentypen und Rolleninstanzen

Der Core definiert Rollentypen. Ein Rollentyp
ist eine Vorlage: er beschreibt, welche
Domaenen und welche Permissions in welcher
Domaene ein Principal haben darf.

Eine Rolleninstanz ist eine konkrete Rolle,
die einem Principal zugewiesen wird. Sie
entsteht aus einem Rollentyp.

Die Admin AI darf Rolleninstanzen aus
existierenden Rollentypen anlegen, wenn:
- der Rollentyp existiert,
- der Rollentyp kein Core-Admin ist,
- die Zuweisung im Rahmen der Berechtigung
  der Admin AI liegt.

Ausnahme: Core-Admins (hoechste Rolle) duerfen
nur vom Menschen angelegt werden. Die Admin AI
darf sich nicht selbst privilegieren.

Siehe docs/ADMIN_AI_SCOPE.md § 4.
