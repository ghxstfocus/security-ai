# Werkzeuge

Uebersicht der Skripte und CLIs. Alle im Projekt-Root
ausfuehrbar.

Voraussetzung: venv ist aktiv oder der explizite Pfad
`.venv/bin/python3` wird verwendet. Alle Beispiele in
dieser Datei nutzen `.venv/bin/python3`.

## scripts/init_db.py

Legt die SQLite-Datenbank an, wendet alle Migrationen aus
`data/migrations/` an und legt (Default) einen Start-Prinicpal
`cli-admin` mit Rolle `admin` an.

Idempotent: existierende DB und existierender Principal werden
nicht ueberschrieben.

    .venv/bin/python3 scripts/init_db.py
        # DB + cli-admin (role=admin)

    .venv/bin/python3 scripts/init_db.py --no-principal
        # nur DB + Migrationen

    .venv/bin/python3 scripts/init_db.py --principal admin --role operator
        # anderer Principal

    .venv/bin/python3 scripts/init_db.py --db /pfad/zur/db.sqlite
        # anderer DB-Pfad (Default: data/inventory.db)

Exit-Code 0 bei Erfolg, 1 bei Fehler.

## scripts/chat_cli.py — entfernt (Phase 16)

Der lokale Chat (chat_cli, Ollama) wurde mit dem Ollama-Rueckbau entfernt. Siehe DESIGN_DECISIONS Paragraph 26 und SECURITY_REVIEW_LOG Punkt 88.

## scripts/approvals_cli.py

Approvals verwalten. DB muss existieren (fail closed).

    .venv/bin/python3 scripts/approvals_cli.py list [--all]
    .venv/bin/python3 scripts/approvals_cli.py show <request_id>
    .venv/bin/python3 scripts/approvals_cli.py approve <request_id> --by X
    .venv/bin/python3 scripts/approvals_cli.py reject  <request_id> --by X \
        [--reason Y]
    .venv/bin/python3 scripts/approvals_cli.py expire
    .venv/bin/python3 scripts/approvals_cli.py count

## scripts/changes_cli.py

Change Requests verwalten. DB muss existieren (fail closed).

    .venv/bin/python3 scripts/changes_cli.py list [--status STATUS] [--all]
    .venv/bin/python3 scripts/changes_cli.py show <change_id>
    .venv/bin/python3 scripts/changes_cli.py create --title X --description Y \
        --by Z --type T
    .venv/bin/python3 scripts/changes_cli.py decide <change_id> --by X
    .venv/bin/python3 scripts/changes_cli.py reject <change_id> --by X \
        [--reason Y]
    .venv/bin/python3 scripts/changes_cli.py deploy <change_id>
    .venv/bin/python3 scripts/changes_cli.py rollback <change_id> --by X \
        [--reason Y]
    .venv/bin/python3 scripts/changes_cli.py cancel <change_id> --by X \
        [--reason Y]
    .venv/bin/python3 scripts/changes_cli.py export <change_id> [--out DIR]
    .venv/bin/python3 scripts/changes_cli.py count

## tools/ (Hintergrundprozesse, systemd-gesteuert)

- tools/event_reader.py (Timer 30s) — liest
  data/events-YYYY-MM-DD.jsonl, ruft
  SecurityAI.process(), Cursor in event_cursor,
  Idempotenz via processed_events.
- tools/fritzbox_watcher.py (Timer 60s) — liest
  Fritz!Box-Hosts via TR-064, schreibt
  device_presence/device_offline nach
  data/events-YYYY-MM-DD.jsonl.

systemd-Units: siehe docs/DEPLOYMENT.md.

## Suche (Dashboard, GET /search?q=...)

Durchsucht werden pro Quelle (LIKE '%q%',
case-insensitiv):

- devices:              identifier, entity_name
- whitelisted_devices:  identifier, entity_name
- changes:              change_id, title
- approvals:            request_id, tool_name, requested_by
- principals:           name
- roles:                name
- permissions:          code
- risk_assessments:     audit_id, event_id, rule_id,
                        tool, category (seit 3.6.18a)

Limit: 20 Treffer pro Quelle (Auflage 368).
Die Suche liefert nur die Quellen, fuer die der
Principal die Berechtigung hat (A525/A526).

### Wert-Synonyme (Punkt 29)

Suchbegriffe werden auf Synonym-Zielwerte erweitert.
Quelle: core/search/synonyms.yaml.
Beispiele:
- alarm        -> category=SECURITY_ALERT.
- verdacht     -> category=SUSPICION.
- freigegeben  -> status=granted (approvals),
                  status=approved (changes).

Kein Quellen-Synonym. "alarme" findet keine
risk_assessments (Punkt 29: Variante 1 verworfen).
Die normale String-Suche bleibt.

### Was die Suche NICHT findet

- Anzeigenamen aus der UI (z. B. "Alarme",
  "Freigaben", "Aenderungen").
- Deutsche Begriffe ("alarm", "alert", "freigabe").
  Punkt 29 in docs/SECURITY_REVIEW_LOG.md:
  Synonym-Mapping ist geplant, aber nicht gebaut.
- Freitext-Felder: description, diff_or_patch,
  rollback_plan, test_plan, args_json,
  decision_reason, notes (Auflage 529).

### Beispiel

- q=CONFIRMED     -> Treffer in Alarme.
- q=confirmed     -> Treffer (case-insensitiv).
- q=alarme        -> leer (Punkt 29).

## Tests

    .venv/bin/python3 -m pytest tests/ -q
        # alle Tests

    .venv/bin/python3 -m pytest tests/unit/test_chat.py -q
        # einzelne Datei

Erwartung nach jedem groesseren Schritt: alle gruen.
