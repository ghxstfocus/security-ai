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

### OP-004: A900 mypy no-untyped-def
- **Status:** open
- **Betroffene Dateien:** —
- **Akzeptanzkriterien:** A900: mypy no-untyped-def (67 Stellen, inzwischen mehr). Kategorie 2.
- **Tests:** —
- **Blockiert von:** —

### OP-006: Planner-Split crasht auf 'out-of-scope'-Architect-Output
- **Status:** open
- **Betroffene Dateien:** `werkstatt/planner.py` (Split-Logik)
- **Akzeptanzkriterien:** Wenn der Architect sagt "out-of-scope" oder "Tests sind OUT-OF-SCOPE" und KEINEN konkreten Task-Plan liefert, bricht Planner-Split ab mit `planner_split_no_tasks` und der Loop endet sauber. Er erzeugt NICHT einen Mega-Task mit 20+ Dateien aus dem Code-Index. Live-Beleg 2026-10-31: OP-005-Loop, Planner-Split lieferte 1 Task "Architect-Loesung umsetzen" mit 24 Dateien (24 Migrations + 2 Tests + 2 Docs + 2 Code-Dateien), obwohl die Aufgabe explizit nur 2 Test-Dateien betraf.
- **Tests:** `tests/test_planner_split.py::test_out_of_scope_kein_mega_task`
- **Blockiert von:** —

### OP-002b1: upsert_seen delegiert an update_last_ip_if_changed
- **Status:** open
- **Betroffene Dateien:** `core/inventory/repository.py`
- **Akzeptanzkriterien:** In `upsert_seen` (repository.py) wird die Zeile `new_ip = ip if ip else existing.last_ip` und die `last_ip`-Spalte im UPDATE entfernt. Stattdessen EIN Aufruf `self.update_last_ip_if_changed(identifier, ip)` NACH dem bestehenden UPDATE und VOR `self._conn.commit()`. KEINE Inline-Duplikation der Logik. `update_last_ip_if_changed` wird tatsaechlich aufgerufen (grep: `self.update_last_ip_if_changed` in upsert_seen-Body). KEINE `_insert_device_history` (bleibt OP-002b2). KEIN Duplikatschutz (bleibt OP-002b3).
- **Tests:** Bestehende Tests in `tests/unit/test_inventory.py` bleiben gruen. Neuer Test `test_upsert_seen_ruft_update_last_ip_if_changed` (mock/Monkey-Patch auf die Methode, prueft Aufruf).
- **Blockiert von:** —
- **Hinweis:** Live-Test 5 v2 (2026-11-01): Builder duplizierte die Logik inline statt zu delegieren. 3× Reviewer-Reject. Phase-Reflection erschoepft. Kleinerer Task-Scope soll das verhindern.

### OP-002b2: _insert_device_history mit Duplikatschutz
- **Status:** open
- **Betroffene Dateien:** `core/inventory/repository.py`
- **Akzeptanzkriterien:** Neue Methode `_insert_device_history(self, device_id, feld, alt, neu, timestamp)` mit Duplikatschutz: VOR dem INSERT ein SELECT auf (device_id, feld, alt, neu, timestamp). Wenn identischer Eintrag existiert: skip (return False). KEINE doppelte Methodendefinition. KEIN Aufruf aus `upsert_seen` (bleibt OP-002b3).
- **Tests:** Neuer Test `test_insert_device_history_kein_duplikat` (2× gleicher Aufruf → 1 DB-Zeile).
- **Blockiert von:** —
- **Hinweis:** Live-Test 5 v2: Builder definierte die Methode 2× (Duplikat im Diff) ohne Duplikatschutz. Reviewer-Reject korrekt. Kleinerer Scope.

### OP-002b3: upsert_seen ruft _insert_device_history nach Diff
- **Status:** open
- **Betroffene Dateien:** `core/inventory/repository.py`
- **Akzeptanzkriterien:** In `upsert_seen`, NACH erfolgreichem `self.update_last_ip_if_changed(...)`, wenn `True` zurueck: rufe `self._insert_device_history(device_id, feld="last_ip", alt=<alter Wert aus SELECT>, neu=<normalize_ip(ip)>, timestamp=ts)`. Atomare Transaktion (commit nur bei Erfolg, sonst rollback + raise). KEINE Inline-Implementierung der History-Logik in upsert_seen.
- **Tests:** Neuer Test `test_upsert_seen_mit_ip_wechsel_history` (Wechsel → 2 DB-Eintraege in device_history mit alt/neu).
- **Blockiert von:** OP-002b1, OP-002b2
- **Hinweis:** Setzt voraus, dass b1 und b2 sauber sind.
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
| OP-005 |
| OP-054 | erledigt 2026-11-01 (Werkstatt b795e14) | Builder-False-Positive gefixt | – | erledigt 2026-10-31 (37a6766) | Test-Umschreiben | – |
| OP-002a | erledigt 2026-11-01 (0c0b901, 4bd9c2a) | normalize_ip + update_last_ip_if_changed | – |
| `docs/DECISIONS.md` | Monolith, 2026-10-31 migriert | `docs/adr/ADR-NNNN-*.md` | nie — ADR-Format ist Pflicht |
| `docs/README.md` | Diaetaxis, 2026-10-31 | `docs/index.md` | nie |
| `PROJECT_VISION.md` (root) | Doku-Bundling, 2026-10-31 | `docs/PROJECT_VISION.md` | nie |
| `docs/PROGRESS.md` | Duplikat, 2026-10-31 | `PROGRESS.md` (root) | nie |
