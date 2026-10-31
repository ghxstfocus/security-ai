# ADR-0027: Datenklassifikation

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §27

---

## 27. Datenklassifikation

Jede Information, die durch den Core geht,
hat eine Vertraulichkeitsstufe:

- **Oeffentlich.** Darf an jeden Cloud-Provider.
- **Intern.** Nur an Provider mit AVV
  (Auftragsverarbeitungsvertrag).
- **Vertraulich.** Nur an Provider mit AVV
  und in der EU oder gleichwertig.
- **Streng vertraulich.** Nur lokal oder
  gar nicht. Kein Cloud-Provider.

Die Firma entscheidet pro Installation,
welche Stufe welchen Provider nutzen darf.

Der Core filtert jede Anfrage an die Admin AI
nach dieser Klassifikation. Was nicht raus
darf, geht nicht raus.

Die Klassifikation ist Datenpflege, nicht
Code. Sie kann im Dashboard angepasst werden
(vom Menschen) oder durch Change Request.
