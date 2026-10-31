# Conventions — Homelab Security AI

Projektspezifische Konventionen. Was hier steht,
gilt fuer dieses Projekt.

Der generische Prozess (Hard-Rules, Fakten-Check-
Takt, Kategorien, Patch-Template, Verifikations-
Reihenfolge, Anti-Patterns, Reviewer-Konventionen,
Rollen) liegt in der Werkstatt:

    /opt/werkstatt/docs/WORKFLOW.md

Die Rollen-Prompts selbst liegen in:

    /opt/werkstatt/agents/

Die Anti-Patterns aus der Praxis liegen im
Werkstatt-Katalog:

    /opt/werkstatt/anti-patterns/katalog.yaml

Dieses Projekt hat KEINE eigene Workflow-Datei
mehr. Was projektspezifisch ist, steht hier.

## 1. Python-Interpreter

/opt/security-ai/.venv/bin/python3

Nicht /usr/bin/python3. Das System-Python hat die
pyproject-Dependencies nicht (Flask, PyYAML,
requests, psutil).

## 2. CWD fuer Tests

/opt/security-ai

detection/rules.yaml, policies/tools.yaml und
core/risk/rules.yaml werden relativ zum CWD
geladen. Tests aus einem anderen Verzeichnis
schlagen fehl.

### Arbeitsverzeichnis

Alle im Projekt verwendeten Dateipfade
(`detection/rules.yaml`, `policies/tools.yaml`,
`core/risk/rules.yaml`, `audit-logs/`, `data/`,
`changes/backups/`) sind relativ zum CWD und
werden nicht aus `__file__` abgeleitet. Deshalb
muessen systemd-Units `WorkingDirectory=/opt/security-ai`
setzen. Die Belege (Tabelle der CWD-relativen
Pfade, Beispiel-Units) stehen ausschliesslich in
`docs/DEPLOYMENT.md` §3d — dort und nur dort,
damit die CWD-Anforderung nicht an zwei Stellen
auseinanderlaeuft.

Randbedingung: Lokale Aufrufe (pytest,
CLI-Skripte) muessen aus dem Projektwurzel-
verzeichnis erfolgen; die venv-Python liegt
unter `/opt/security-ai/.venv/bin/python3`.

## 3. Git-Remote/Branch

origin/main

## 4. Testzahl-Quelle

/opt/security-ai/.venv/bin/python3 -m pytest --collect-only -q | tail -1

Diese Zahl ist die Wahrheit. Nicht schaetzen, nicht
aus dem Gedaechtnis.

## 5. Doku-Dateien in diesem Projekt

Pflicht:

- docs/STATUS.md — aktueller Stand.
- docs/ROADMAP.md — Phasen und Ausblick.
- docs/adr/ — Design-Entscheidungen.
- docs/SECURITY_LOG.md — Sicherheitsentscheidungen.
- docs/CONVENTIONS.md — diese Datei.
- CHANGELOG.md — chronologische Aenderungen.

Optional (projektweit):

- docs/ARCHITECTURE.md, docs/SECURITY.md,
  docs/PERMISSIONS.md, docs/PROTOCOL.md,
  docs/DEPLOYMENT.md, docs/WEB_SECURITY_CHECKLIST.md,
  docs/ADMIN_AI_SCOPE.md, docs/INCONSISTENCIES_FOUND.md,
  docs/WERKZEUGE.md, docs/ICONS.md, docs/NTFY.md.
- PROJECT_VISION.md, README.md.

Status-Icons in ROADMAP und STATUS:

- ✅ abgeschlossen
- 🔨 in Arbeit
- 💡 geplant
- ❌ abgebrochen
- ⏸ pausiert

## 6. Reviewer-Pflicht

Kategorie 3 laut Werkstatt-WORKFLOW, Abschnitt
"Kategorien". Code VOR Ausfuehrung an den Reviewer.
Kein Improvisieren nach NO-GO.

## 7. Keine Umlaute in Code-Bloecken

In Code-Bloecken (Shell, Python, Jinja): oe, ue,
ae, ss statt Umlaute.

In Kommentaren und Doku erlaubt.

## 8. scripts/* sind Werkzeuge

Keine Bibliothek. Nur aus /opt/security-ai
importierbar. Nicht aus anderen Modulen.

## Verweis

- docs/STATUS.md — aktueller Stand.
- /opt/werkstatt/docs/WORKFLOW.md — generischer Prozess.
- /opt/werkstatt/agents/ — Rollen-Prompts.
- /opt/werkstatt/anti-patterns/katalog.yaml — Anti-Patterns.
