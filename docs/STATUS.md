# Status — security-ai

Format aus `DOC_CONVENTIONS.md` §5. Nur offene Punkte.
Letzte Aktualisierung: 2026-10-31.

## Kennzahlen

- HEAD: ffef6b4 (origin/main synchron).
- Branch: main.
- Working Tree: sauber.
- Tests: 1343 collected (Stand 2026-11-01).
- ruff 0.16.9: All checks passed.
- mypy: 1353 Fehler in 73 Dateien (Altlast,
  ueberwiegend no-untyped-def in Tests).
- Python: /opt/security-ai/.venv/bin/python3.

## Aktuelle Phase

Phase 3.6 (Web-Dashboard) ist funktional
abgeschlossen. Arbeit laeuft ueber die Werkstatt
(Punkte und Zwischenbloecke).

## Offene Punkte

### OP-003: ruff-Regelschaerfung
- **Status:** open
- **Betroffene Dateien:** —
- **Akzeptanzkriterien:** Punkt 53b: ruff-Regelschaerfung (PL, TRY, ANN, S, T20, ARG). Kategorie 3, eigener Block mit Bestandsaufnahme pro Regel-Gruppe.
- **Tests:** —
- **Blockiert von:** —

### OP-004: mypy operator-Fehler in core/checks/__init__.py:76

- **Status:** open
- **Betroffene Dateien:** `core/checks/__init__.py`
- **Akzeptanzkriterien:** `mypy core/checks/__init__.py` muss 0 Fehler zeigen. Aktuell 2 Fehler in Zeile 76 (`check_port_range`, `return min_port <= port <= max_port`):
error: Unsupported operand types for >= ("int" and "object") [operator]
error: Unsupported operand types for <= ("int" and "object") [operator]

text
Kopieren
Herunterladen
Ursache: `min_port`/`max_port` sind als `object` typisiert. mypy narrowt sie nach den `isinstance`-Guards nicht auf `int`, weil die Bedingung `if not isinstance(min_port, int) or isinstance(min_port, bool)` das Narrowing blockiert.
Fix: entweder explizites `typing.cast(int, ...)` nach den Guards, oder die Bedingungen umstrukturieren (separate `if not isinstance(...): return False`-Zeilen, dann separater `bool`-Ausschluss).
Keine Verhaltensaenderung: die Funktion liefert weiter `False` bei Nicht-Int-Ports und `True` bei int im Bereich. Bestehende Tests in `tests/unit/test_checks.py` bleiben gruen.
- **Tests:** `tests/unit/test_checks.py::test_check_port_range_invalid_bounds` (existiert, deckt bool/str/None-Grenzen ab).
- **Blockiert von:** —
- **Hinweis:** Urspruengliche OP-004-Beschreibung ('A900 mypy no-untyped-def, 67 Stellen') war eine **Fehldiagnose**. Messung 2026-11-01: 0 untyped-def-Fehler in `core/` bei aktivem `disallow_untyped_defs = true` (pyproject.toml:55); der grep auf 105 war ein False-Positive auf mehrzeilige Signaturen. Echte mypy-Fehler: **2**, beide in `core/checks/__init__.py:76` (`operator`, nicht `no-untyped-def`). A900 ist kein ruff-Code (ruff 0.16.9 kennt das nicht). Diese OP deckt den echten, konkreten mypy-Befund ab — klein, loop-tauglich, Test existiert.

### OP-006: Planner-Split crasht auf 'out-of-scope'-Architect-Output
- **Status:** open
- **Betroffene Dateien:** `werkstatt/planner.py` (Split-Logik)
- **Akzeptanzkriterien:** Wenn der Architect sagt "out-of-scope" oder "Tests sind OUT-OF-SCOPE" und KEINEN konkreten Task-Plan liefert, bricht Planner-Split ab mit `planner_split_no_tasks` und der Loop endet sauber. Er erzeugt NICHT einen Mega-Task mit 20+ Dateien aus dem Code-Index. Live-Beleg 2026-10-31: OP-005-Loop, Planner-Split lieferte 1 Task "Architect-Loesung umsetzen" mit 24 Dateien (24 Migrations + 2 Tests + 2 Docs + 2 Code-Dateien), obwohl die Aufgabe explizit nur 2 Test-Dateien betraf.
- **Tests:** `tests/test_planner_split.py::test_out_of_scope_kein_mega_task`
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
| OP-002b1 | erledigt 2026-11-01 (dffa860) | Delegation + None-Guard | – |
| OP-054 | erledigt 2026-11-01 (Werkstatt b795e14) | Builder-False-Positive gefixt | – |
| OP-005 | erledigt 2026-10-31 (37a6766) | Test-Umschreiben | – |
| OP-002a | erledigt 2026-11-01 (0c0b901, 4bd9c2a) | normalize_ip + update_last_ip_if_changed | – |
| `docs/DECISIONS.md` | Monolith, 2026-10-31 migriert | `docs/adr/ADR-NNNN-*.md` | nie — ADR-Format ist Pflicht |
| `docs/README.md` | Diaetaxis, 2026-10-31 | `docs/index.md` | nie |
| `PROJECT_VISION.md` (root) | Doku-Bundling, 2026-10-31 | `docs/PROJECT_VISION.md` | nie |
| `docs/PROGRESS.md` | Duplikat, 2026-10-31 | `PROGRESS.md` (root) | nie |
| OP-002b2 | erledigt 2026-11-01 (ef413bd) | Loop-Nachzug manuell (Loop rc=1, Methode+Test manuell) | – |
| OP-002b3 | erledigt 2026-11-01 (09cb89d/f2f126c) | Loop-Nachzug erfolgreich (4/4 Tasks, rc=0) | – |
