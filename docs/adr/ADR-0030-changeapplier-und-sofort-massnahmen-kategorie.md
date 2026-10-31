# ADR-0030: ChangeApplier und Sofort-Massnahmen-Kategorie

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §30

---

## 30. ChangeApplier und Sofort-Massnahmen-Kategorie

ChangeApplier (harness/versioning/applier.py) ueberfuehrt
Change-Requests in den Systemzustand. Drei Eigenschaften sind
verbindlich:

- Fail closed: unbekannte Aktion, fehlende Berechtigung oder
  Audit-Fehler fuehren zum Abbruch. Kein stiller Durchlauf.
- Backup/Restore: vor jeder Aenderung wird der Vorzustand
  gesichert; Rollback stellt ihn wieder her.
- Idempotenz: wiederholte Anwendung derselben Aenderung fuehrt
  nicht zu doppelten Effekten.

Sofort-Massnahmen-Kategorie: BLOCK und ISOLATE sind destruktiv
(sie veraendern den Systemzustand). Sie brauchen eine eigene
Permission (sofortmassnahme.execute), RBAC im Service-Layer und
einen Audit-Eintrag (kind=sofortmassnahme_executed) mit Akteur,
Ziel, Aktion und Ergebnis. Reine Lese-Aktionen bleiben ohne
Sofort-Massnahme.

Begruendung: Destruktive Aktionen ohne Backup, ohne Idempotenz
und ohne Audit sind nicht rueckholbar und nicht nachweisbar.
Fail closed verhindert, dass ein Fehler still durchlaeuft.

---
