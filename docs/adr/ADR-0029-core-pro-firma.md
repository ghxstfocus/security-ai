# ADR-0029: Core pro Firma

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §29

---

## 29. Core pro Firma

Jede Firma installiert ihren eigenen Core.
Keine Mandantenfaehigkeit auf einer
gemeinsamen Installation.

Konsequenzen:
- Keine Mandanten-Spalte in Tabellen.
- Keine Trennung zwischen Kunden auf
  Anwendungsebene.
- Eigene Datenbank pro Firma.
- Eigene Zertifikate pro Firma.
- Eigene Rollen, Domaenen, Endpunkte
  pro Firma.
- Eigene Admin AI (Cloud der Firma).
- Eigene Kunden-KI (Cloud der Firma).

Foederation zwischen Installationen ist
optional (siehe docs/PROTOCOL.md). Eine
Admin AI kann mehrere Cores ihrer Firma
korrelieren. Kein Core sieht einen anderen.

Der Core laeuft autark. Er funktioniert auch
ohne Admin AI und ohne Kunden-KI. Was fehlt,
ist die Intelligenz-Schicht, nicht die
Sicherheitsbasis.
