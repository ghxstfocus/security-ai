# Naechster Bau-Block

Kontext: `docs/STATUS.md`, Abschnitt "Offene Punkte", Punkt 7 (A900), HEAD `c9142a7`.
Dieser Block ergaenzt ausschliesslich Typannotationen und aendert kein Verhalten.

## Ziel

Durchgaengige Typannotationen in `harness/versioning/applier.py` ergaenzen, ohne das Laufzeitverhalten zu veraendern. Alle oeffentlichen und privaten Funktionen, Methoden, Fehlerklassen und frozen Result-Dataclasses erhalten vollstaendige Parameter- und Rueckgabetypen. Die bestehenden Signaturen bleiben semantisch identisch; es werden nur Annotationen hinzugefuegt.

## Betroffene Dateien

- `harness/versioning/applier.py` — Annotations-Scope: `__init__`, `apply`, `rollback`, die vier Fehlerklassen sowie die zwei frozen Result-Dataclasses.
- `tests/unit/test_applier.py` — Regressionsschutz: prueft die bestehenden Signaturen indirekt und muss unveraendert gruen bleiben.

Keine Aenderung an `docs/STATUS.md`, `docs/ROADMAP.md`, `docs/DECISIONS.md` oder `docs/SECURITY_LOG.md` in diesem Block.

## Akzeptanzkriterien

- Alle Funktionen, Methoden, Fehlerklassen und Dataclasses in `harness/versioning/applier.py` tragen vollstaendige Typannotationen fuer Parameter und Rueckgabewerte.
- Kein Verhalten aendert sich: Signaturen bleiben semantisch identisch, nur Annotationen kommen hinzu.
- `ruff check` laeuft auf `harness/versioning/applier.py` ohne neue Verletzungen durch.
- `tests/unit/test_applier.py` bleibt unveraendert und laeuft gruen.
- Keine API-Umbenennung, keine neuen Abhaengigkeiten.

## Testfaelle

- Bestehende Tests in `tests/unit/test_applier.py` laufen unveraendert gruen (Regressionsschutz fuer `apply`, `rollback` und Fehlerklassen).
- Import von `harness/versioning/applier.py` schlaegt nicht fehl (Modul laedt ohne Fehler).
- `ruff check harness/versioning/applier.py` meldet keine neuen Verletzungen.

## Prioritaet-Begruendung

Punkt 7 (A900) ist gegenueber den anderen offenen Punkten aus `docs/STATUS.md` und dem Block "Naechster Bau-Block" in `docs/ROADMAP.md` vorzuziehen, weil er einen eng zugeschnittenen, deterministisch pruefbaren Scope hat: eine einzige Datei, rein additive Annotationen, kein Verhaltensrisiko. Breitere Bloecke (Punkt 6: ruff-Regelschaerfung ueber den ganzen Baum) oder nicht deterministisch pruefbare Bloecke (Punkt 2 systemd-WorkingDirectory, Punkt 4 .env.example, Punkt 5 last_ip) werden bewusst zurueckgestellt. Die Auswahl reduziert das Risiko, dass der Loop aus der langen Liste selbst priorisieren muss.
