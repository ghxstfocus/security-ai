# AGENTS.md — security-ai

Verbindliche Constitution. Lese-Reihenfolge:

1. `docs/STATUS.md` — offene Punkte
2. `docs/ROADMAP.md` — Phasen, Milestones
3. `docs/ARCHITECTURE.md` — Modul-Map
4. `docs/CONVENTIONS.md` — Coding-Regeln
5. `docs/adr/` — Entscheidungen
6. `docs/glossary.md` — Begriffe
7. `docs/index.md` — Einstieg

Stand: 2026-10-31. Projekt: `/opt/security-ai`.

## Zweck

Sicherheits-/AI-System. Host-Scanner, Detection, Risk Engine, Approval-
Workflow, ChangeApplier, Web-Dashboard.

## Struktur

- `apps/` — Web-Apps
- `core/` — Kernlogik (Checks, Risk, Policy, Planning)
- `harness/` — Versionierung, Approvals
- `tools/` — externe Werkzeuge
- `tests/` — Test-Suite
- `docs/` — Doku

## Hard-Rules (Kurzform)

- Ein Fakt = eine Quelle.
- Was erledigt ist, fliegt aus `STATUS.md` nach `PROGRESS.md`.
- Keine Behauptung ohne Code-Beleg.
- Fail closed bei Fehlern in der Detection.

## Loop

Der Loop liest in obiger Reihenfolge. `docs/STATUS.md` ist primaere
Aufgabenquelle bei vagen Auftraegen.
