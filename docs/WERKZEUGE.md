# Werkzeuge

Uebersicht der Skripte und CLIs. Alle im Projekt-Root
ausfuehrbar.

## scripts/init_db.py

Legt die SQLite-Datenbank an, wendet alle Migrationen aus
`data/migrations/` an und legt (Default) einen Start-Prinicpal
`cli-admin` mit Rolle `admin` an.

Idempotent: existierende DB und existierender Principal werden
nicht ueberschrieben.

    python3 scripts/init_db.py
        # DB + cli-admin (role=admin)

    python3 scripts/init_db.py --no-principal
        # nur DB + Migrationen

    python3 scripts/init_db.py --principal admin --role operator
        # anderer Principal

    python3 scripts/init_db.py --db /pfad/zur/db.sqlite
        # anderer DB-Pfad (Default: data/inventory.db)

Exit-Code 0 bei Erfolg, 1 bei Fehler.

## scripts/chat_cli.py

Chat mit der lokalen KI (Ollama). Nutzt ChatService
(Service-Schicht).

    python3 scripts/chat_cli.py --principal cli-admin
        # interaktiv, "exit" beendet

    python3 scripts/chat_cli.py --principal cli-admin \
        --question "Was kannst du?"
        # einmalige Frage

    python3 scripts/chat_cli.py --principal cli-admin --whoami
        # Rolle + Permissions anzeigen

Optionen:

- `--principal NAME`   (Pflicht)
- `--question TEXT`    einmalige Frage, sonst interaktiv
- `--whoami`           Identitaets-Auskunft, keine Frage
- `--detail`           Detail-Antwort ohne LLM
                       (braucht chat.detail)
- `--include-details`  Rohdaten in den Prompt
                       (braucht chat.include_details)
- `--model NAME`       Modell-Override (Default aus .env)
- `--base-url URL`     Ollama-URL (Default aus .env)
- `--timeout N`        LLM-Timeout in Sekunden
- `--no-bootstrap`     kein Auto-Init der DB (fail closed)
- `--db PATH`          SQLite-DB (Default: data/inventory.db)
- `--migrations-dir`   Migrations-Ordner
- `--audit-base-dir`   Audit-Log-Ordner

Auto-Bootstrap: fehlt die DB, wird sie angelegt und `cli-admin`
(role=admin) erzeugt. Mit `--no-bootstrap` stattdessen Exit 1.

## scripts/approvals_cli.py

Approvals verwalten. DB muss existieren (fail closed).

    python3 scripts/approvals_cli.py list [--all]
    python3 scripts/approvals_cli.py show <request_id>
    python3 scripts/approvals_cli.py approve <request_id> --by X
    python3 scripts/approvals_cli.py reject  <request_id> --by X \
        [--reason Y]
    python3 scripts/approvals_cli.py expire
    python3 scripts/approvals_cli.py count

## scripts/changes_cli.py

Change Requests verwalten. DB muss existieren (fail closed).

    python3 scripts/changes_cli.py list [--status STATUS] [--all]
    python3 scripts/changes_cli.py show <change_id>
    python3 scripts/changes_cli.py create --title X --description Y \
        --by Z --type T
    python3 scripts/changes_cli.py decide <change_id> --by X
    python3 scripts/changes_cli.py reject <change_id> --by X \
        [--reason Y]
    python3 scripts/changes_cli.py deploy <change_id>
    python3 scripts/changes_cli.py rollback <change_id> --by X \
        [--reason Y]
    python3 scripts/changes_cli.py cancel <change_id> --by X \
        [--reason Y]
    python3 scripts/changes_cli.py export <change_id> [--out DIR]
    python3 scripts/changes_cli.py count

## Tests

    python3 -m pytest tests/ -q
        # alle Tests

    python3 -m pytest tests/unit/test_chat.py -q
        # einzelne Datei

Erwartung nach jedem groesseren Schritt: alle gruen.
