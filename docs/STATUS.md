# Status

Aktueller Stand des Projekts. Kurz halten.
Details in `docs/ROADMAP.md` (Phasen) und
`docs/DECISIONS.md` (Design).

Letzte Aktualisierung: 2026-10-26.

## Kennzahlen

- HEAD: c9142a7 (origin/main synchron).
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

Letzte abgeschlossene Bloecke:

- PB-66: nmap_scan ToolArgumentValueError
  (d135fd4, 2026-10-15).
- PB-65: notify_ntfy Unit-Tests
  (2aa2b0b, 2026-10-15).
- PB-64: notify_ntfy Argument-Checks
  (8db36f7, 2026-10-15).
- PB-63: whois ToolArgumentValueError
  (3bb5917, 2026-10-14).
- PB-62 (alt): 2199-Zwischenstand dns_lookup
  IPv6-Feld (35e5178, 2026-10-13).

## ChangeApplier

Status: ✅ implementiert (`harness/versioning/applier.py`, 277 Zeilen, RERUN-80).
- `apply()` und `rollback()` sind implementiert (kein Stub mehr).
- Fail-closed-Semantik: unbekannter Typ, fehlender Handler oder Audit-Fehler -> `ApplierError`.
- Idempotenz: zweiter `apply()` auf DEPLOYED -> `idempotent_skip=True`.
- Backup: `changes/backups/<change_id>.json`.

## Phase 19 — ChangeApplier und Sofort-Massnahmen-Kategorie

Status: ✅ abgeschlossen (U1-U5). Details in docs/ROADMAP.md,
Begruendung in docs/DECISIONS.md Paragraph 30.

Unterbloecke:

- ✅ U1: ChangeApplier-Grundgeruest (harness/versioning/applier.py,
  Backup/Restore, Idempotenz, Fail-closed).
- ✅ U2: ChangeApplier-Integration in ChangeService
  (change_deployed, change_rolled_back, Audit-Pflicht).
- ✅ U3: Sofort-Massnahmen-Kategorie (BLOCK, ISOLATE als
  destruktive Aktionen; Berechtigung + Audit-Pflicht).
- ✅ U4: RBAC und Audit fuer Sofort-Massnahmen
  (eigene Permission, Audit-Kind, fail closed).
- ✅ U5: Tests und Doku-Nachzug (Unit-Tests, STATUS, ROADMAP,
  DECISIONS, SECURITY_LOG).

Verweis: ChangeApplier in harness/versioning/applier.py,
Sofort-Massnahmen-Kategorie in docs/DECISIONS.md Paragraph 30,
Sicherheitsentscheidungen in docs/SECURITY_LOG.md.

## Refactoring core/checks/ (Phasen, Docstrings, Typen, Grenzfall-Tests)

Status: ✅ abgeschlossen (t7, Gesamtverifikation und Doku-Nachzug).

Durchgefuehrt:

- Bestehende `check_port_*`-Funktionen in logische Phasen
  gegliedert (Analyse, Dokumentation, Tests).
- Alle `check_port_*`-Funktionen mit Docstrings und
  Typannotationen versehen.
- Fuer jede `check_port_*`-Funktion mindestens ein
  Grenzfall-Test ergaenzt.

Verifikation (t7):

- `pytest -q` aus `/opt/security-ai` mit
  `.venv/bin/python3` laeuft gruen.
- Testzahl gegen Baseline (1334 collected) geprueft;
  aktuelle Zahl siehe Kennzahlen oben.
- `ruff` auf den geaenderten Dateien: keine neuen
  Befunde.
- `mypy` auf den geaenderten Dateien: keine neuen
  Fehler gegenueber Altlast (1353 Fehler in 73 Dateien).

## Naechster Bau-Block

Offen aus `docs/ROADMAP.md`:

- Host-Scanner (Phase 3.8).
- Endpoint-Watcher.
- Chat als Aktions-Schnittstelle.
- Token-Mechanik.
- Anbindungs-Registry.
- Cloud-AI-Anbindung.
- Kunden-KI-Basis.
- LLM-Rolle klaeren.

## Offene Punkte (aus SECURITY_LOG.md)

1. AuditReaderError-Namenskollision:
   `core/reporting/audit_reader.py::AuditReaderError`
   hat denselben Namen wie der fruehere Service-
   Fehler. Service-Seite umbenannt zu
   `AuditReaderServiceError`. Modul-Seite in
   Phase 3.6.9+ umbenennen.

2. systemd `WorkingDirectory=/opt/security-ai`:
   `audit-logs/` und `detection/rules.yaml` werden
   relativ zum CWD gelesen. Deployment-Doku +
   Unit-File in Phase 3.6.9.

3. Rollen-Review: kein Principal ohne Rolle.
   Siehe SECURITY_LOG.md.

4. Punkt 45: verwaiste .env.example-Variablen
   (Kategorie 1, Doku).

5. Punkt 49: last_ip nur bei Diff-Events
   (Beobachtungsstand).

6. Punkt 53b: ruff-Regelschaerfung
   (PL, TRY, ANN, S, T20, ARG).
   Kategorie 3, eigener Block mit
   Bestandsaufnahme pro Regel-Gruppe.

7. A900: mypy no-untyped-def (67 Stellen,
   inzwischen mehr). Kategorie 2.

## Umgebung

- Container: CT102 (security-ai,
  192.168.178.117, Tailscale 100.116.205.98).
- Projektordner: /opt/security-ai.
- GitHub: git@github.com:ghxstfocus/security-ai.git.
- Debian 12, Python 3.11, pytest 9.1.1 (venv).
- Zugriff: https://security-ai (Tailnet).
- Ollama entfernt (Phase 16).

## Verweise

- `docs/ROADMAP.md` — Phasen und Ausblick.
- `docs/DECISIONS.md` — Design-Entscheidungen.
- `docs/SECURITY_LOG.md` — Sicherheits-Entscheidungen.
- `docs/CONVENTIONS.md` — projektspezifische Konventionen.
## Phase 18 — Guardrails laden und nutzen

U1-U12 done. U13 (Doku-Nachzug) folgt in diesem Block. Details in docs/ROADMAP.md.

