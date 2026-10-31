# Status — security-ai

Format aus `DOC_CONVENTIONS.md` §5. Nur offene Punkte.
Letzte Aktualisierung: 2026-10-31.

## Kennzahlen

- HEAD: ffef6b4 (origin/main synchron).
- Branch: main.
- Working Tree: sauber.
- Tests: siehe aktuelle pytest-Ausgabe (mind. 1334 collected).
- ruff 0.16.9: All checks passed.
- mypy: 1353 Fehler in 73 Dateien (Altlast,
  ueberwiegend no-untyped-def in Tests).
- Python: /opt/security-ai/.venv/bin/python3.

## Aktuelle Phase

Phase 3.6 (Web-Dashboard) ist funktional
abgeschlossen. Arbeit laeuft ueber die Werkstatt
(Punkte und Zwischenbloecke).

## Offene Punkte

### OP-001: systemd WorkingDirectory
- **Status:** open
- **Betroffene Dateien:** —
- **Akzeptanzkriterien:** systemd `WorkingDirectory=/opt/security-ai`: `audit-logs/` und `detection/rules.yaml` werden relativ zum CWD gelesen. Deployment-Doku + Unit-File in Phase 3.6.9.
- **Tests:** —
- **Blockiert von:** —

### OP-002: last_ip nur bei Diff-Events
- **Status:** open
- **Betroffene Dateien:** —
- **Akzeptanzkriterien:** Punkt 49: last_ip nur bei Diff-Events (Beobachtungsstand).
- **Tests:** —
- **Blockiert von:** —

### OP-003: ruff-Regelschaerfung
- **Status:** open
- **Betroffene Dateien:** —
- **Akzeptanzkriterien:** Punkt 53b: ruff-Regelschaerfung (PL, TRY, ANN, S, T20, ARG). Kategorie 3, eigener Block mit Bestandsaufnahme pro Regel-Gruppe.
- **Tests:** —
- **Blockiert von:** —

### OP-004: A900 mypy no-untyped-def
- **Status:** open
- **Betroffene Dateien:** —
- **Akzeptanzkriterien:** A900: mypy no-untyped-def (67 Stellen, inzwischen mehr). Kategorie 2.
- **Tests:** —
- **Blockiert von:** —

## Umgebung

- Container: CT102 (security-ai,
  192.168.178.117, Tailscale 100.116.205.98).
- Projektordner: /opt/security-ai.
- GitHub: git@github.com:ghxstfocus/security-ai.git.
- Debian 12, Python 3.11, pytest 9.1.1 (venv).
- Zugriff: https://security-ai (Tailnet).
- Ollama entfernt (Phase 16).

## Verweise

- [`ROADMAP.md`](ROADMAP.md) — Phasen und Ausblick.
- `docs/adr/` — Design-Entscheidungen (ADRs).
- [`SECURITY_LOG.md`](SECURITY_LOG.md) — Sicherheits-Entscheidungen.
- [`CONVENTIONS.md`](CONVENTIONS.md) — projektspezifische Konventionen.

## Delete-Zone

| Pfad | Warum entfernt | Ersetzt durch | Wiedereinfuehrung |
|---|---|---|---|
| `docs/DECISIONS.md` | Monolith, 2026-10-31 migriert | `docs/adr/ADR-NNNN-*.md` | nie — ADR-Format ist Pflicht |
| `docs/README.md` | Diaetaxis, 2026-10-31 | `docs/index.md` | nie |
| `PROJECT_VISION.md` (root) | Doku-Bundling, 2026-10-31 | `docs/PROJECT_VISION.md` | nie |
| `docs/PROGRESS.md` | Duplikat, 2026-10-31 | `PROGRESS.md` (root) | nie |
