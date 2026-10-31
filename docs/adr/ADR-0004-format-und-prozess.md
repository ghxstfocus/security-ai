# ADR-0004: Format und Prozess

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §4

---

## 4. Format und Prozess

- Keine Umlaute in Code-Bloecken (oe, ue, ae, ss).
- Kein sed auf Python-Code. Patches per Python-Skript
  (Path.read_text/replace/write_text).
- Nach jedem Schreiben: wc -l, py_compile, Test, git commit.
- Bei langen Dateien zwei oder drei Bloecke.
- Bei Fehlern: kurze Ursache, dann Fix, keine langen Vorreden.
- Auto-Fix-Regeln pruefen, nicht blind anwenden:
  siehe WORKFLOW.md, Abschnitt "Auto-Fix-Regeln pruefen,
  nicht blind anwenden" (B010/TypeVar, Punkt 41).
- Lint-Auflagen: erst messen, dann entscheiden.
  `ruff check --show-settings` zeigt die aktive
  Regel-Liste. `ruff check . --statistics` ist der
  reproduzierbare Stand. `--select <CODE>` forciert
  eine Regel, auch wenn sie nicht im Default-Satz
  waere. Keine Config-Aenderung ohne diese Messung.
  Siehe SECURITY_REVIEW_LOG Punkt 53.

---
