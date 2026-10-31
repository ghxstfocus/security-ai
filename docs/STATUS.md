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

### OP-002a: normalize_ip + update_last_ip_if_changed (Diff-Check, isoliert)
- **Status:** open
- **Betroffene Dateien:** `core/inventory/device.py`, `core/inventory/repository.py`
- **Akzeptanzkriterien:** `normalize_ip(value)` in `device.py` (leer/None -> None, parsebar -> kanonisch via ipaddress, unparsebar -> None). `update_last_ip_if_changed(self, identifier, ip)` in `repository.py`: SELECT last_ip, vergleiche via normalize_ip, UPDATE nur bei Diff. Rueckgabe: True = geschrieben, False = keine Aenderung / unbekannter identifier. KEIN `device_history`-Insert (OP-002b). KEIN `upsert_seen`-Umbau (OP-002b). Keine Migration.
- **Tests:** `tests/unit/test_inventory.py` (Mensch schreibt): `test_normalize_ip_*` (5 Faelle), `test_update_last_ip_if_changed_*` (3 Faelle: Erstschreiben, unveraendert, Wechsel).
- **Blockiert von:** —

### OP-002b: upsert_seen delegiert + device_history-Insert
- **Status:** open
- **Betroffene Dateien:** `core/inventory/repository.py`
- **Akzeptanzkriterien:** `upsert_seen(identifier, ip=X)` ruft `update_last_ip_if_changed(identifier, X)` auf statt `last_ip = ?` direkt zu schreiben. Bei Diff: zusaetzlich `INSERT INTO device_history` mit (device_id, feld="last_ip", alt, neu, timestamp). Bestehende Tests `test_upsert_seen_empty_ip_does_not_overwrite` etc. bleiben gruen. Kein Schema-Change.
- **Tests:** `tests/unit/test_inventory.py` (Mensch): `test_upsert_seen_kein_doppel_history`, `test_upsert_seen_mit_ip_wechsel_history`.
- **Blockiert von:** OP-002a

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

### OP-005: Doku-Assertion-Tests auf migrierte Struktur umschreiben
- **Status:** open
- **Betroffene Dateien:** `tests/unit/test_docs_status.py`, `tests/unit/test_docs_decisions.py`
- **Akzeptanzkriterien:** (a) `test_docs_status.py` prueft Phase-19-Abschnitt in `PROGRESS.md` (nicht mehr `docs/STATUS.md`), weil Phase 19 am 2026-10-31 nach PROGRESS.md migriert wurde. (b) `test_docs_decisions.py` prueft ChangeApplier-Paragraph 30 in `docs/adr/ADR-0030-changeapplier-und-sofort-massnahmen-kategorie.md` (nicht mehr `docs/DECISIONS.md`, Datei am 2026-10-31 geloescht). (c) `pytest tests/unit/test_docs_status.py tests/unit/test_docs_decisions.py -q` ist gruen. (d) Kein anderer Test gebrochen (`pytest -q`).
- **Tests:** `pytest tests/unit/test_docs_status.py tests/unit/test_docs_decisions.py -q`
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
