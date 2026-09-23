# Inkonsistenzen (ausgelagert)

Sammlung von Inkonsistenzen zwischen Dokumenten,
Code und Doku. Ausgelagert aus
`docs/SECURITY_REVIEW_LOG.md`, damit dort nur
Sicherheits-Entscheidungen und offene Punkte stehen.

## Struktur

Pro Eintrag:

    ## Inkonsistenz <N> — <kurzer Titel>
    Urspruenglich in: <Datei> #<N>
    Datum der Auslagerung: YYYY-MM-DD
    Status: offen | gefixt (Commit <hash>)
    Befund: <was>
    Empfehlung: <wie beheben>

## Regeln

- NICHT loeschen. Immer verweisen.
- Historie bleibt.
- Nur echte Widersprueche. Offene Punkte
  (noch nicht erledigt, aber nicht falsch) bleiben
  in `docs/SECURITY_REVIEW_LOG.md`.

## Bestand

Stand 2026-09-23 (Doku-Audit nach Phase 3.6.8):
keine Inkonsistenzen gefunden. Die Datei bleibt als
Ablage fuer kuenftige Funde.
