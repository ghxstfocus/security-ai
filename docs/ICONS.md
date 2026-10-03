# Icons — Konvention fuer die Doku

Status-Marker in allen Markdown-Dateien.

## Status

| Icon | Bedeutung |
|------|-----------|
| ✅ | done / laeuft / abgeschlossen |
| 🔨 | in Arbeit / wip |
| 💡 | idea / geplant / vorgemerkt |
| ❌ | verworfen / entfaellt |

## Regeln

- Nur in Doku-Markdown. Nicht in Code-Kommentaren.
- Nach dem Icon ein Leerzeichen, dann Text.
- Keine Prioritaets-Icons (🔴🟡🟢).
- Kein ⏸ (pausiert wird als 💡 gefuehrt).

## Migration 2026-10-03

Alte ASCII-Marker wurden umgestellt:

- `[x]` -> ✅
- `[~]` -> 🔨
- `[ ]` -> 💡
- `(verworfen)` -> ❌

Runde 1 (2026-10-03): ICONS.md, PROJECT_VISION.md,
docs/PHASES.md, docs/SECURITY_REVIEW_LOG.md.
Runde 2 (offen): WEB_SECURITY_CHECKLIST,
DEPLOYMENT, SECURITY, ARCHITECTURE, WORKFLOW.
