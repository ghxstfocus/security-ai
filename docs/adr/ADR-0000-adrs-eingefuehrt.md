# ADR-0000: ADRs eingefuehrt (Migration aus DECISIONS.md)

- **Status:** accepted
- **Datum:** 2026-10-31
- **Kontext:** `docs/DECISIONS.md` war ein Monolith (1896 Zeilen).
  Der Loop kann daraus keine einzelne Entscheidung referenzieren.
- **Entscheidung:** Entscheidungen werden in einzelne ADRs unter
  `docs/adr/` ueberfuehrt. Dateinamen tragen die Sektionsnummer aus
  `DECISIONS.md` (`ADR-NNNN-<slug>.md`).
- **Konsequenzen:** Einzelne Entscheidungen sind verlinkbar. Der
  Index `docs/adr/README.md` listet alle. `DECISIONS.md` entfaellt.
