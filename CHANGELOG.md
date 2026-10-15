# Changelog

Alle nennenswerten Aenderungen an diesem Projekt,
neueste zuerst. Format: Datum, Commit, Kurzbeschreibung.

Quelle der Wahrheit ist `git log`. Diese Datei fasst
zusammen und ist die menschenlesbare Chronik.

## 2026-10-15

- `c9142a7` test(tools): nmap_scan — Unit-Tests fuer Argument-Validierung.
- `d135fd4` refactor(tools): nmap_scan — ToolArgumentValueError statt ToolArgumentError.
- `2aa2b0b` test(workbench): notify_ntfy — acht Tests fuer ToolArgumentValueError.
- `8db36f7` fix(workbench): notify_ntfy — Nutzereingabe-Checks auf ToolArgumentValueError.
- Doku-Migration: PHASES -> ROADMAP, DESIGN_DECISIONS -> DECISIONS,
  SECURITY_REVIEW_LOG -> SECURITY_LOG. Neue Dateien STATUS.md
  und CHANGELOG.md. CONTEXT_PROMPT.md und REVIEWER_HANDOFF.md entfernt.

## 2026-10-14

- `3bb5917` fix(workbench): whois — Nutzereingabe-Checks auf ToolArgumentValueError.

## 2026-10-13

- `35e5178` feat(workbench): 2199-Zwischenstand — dns_lookup IPv6-Feld.
- `c593cb8` test(workbench): 2199-Zwischenstand — DNS-Fehlerfall ergaenzt.
- `3ccb883` test(workbench): Traceroute-Binary-Fehler-Fall ergaenzt.

## 2026-10-12

- `dd3048b` test(workbench): PingError-Fall bei LXC-Ping ergaenzt.
- `f913eac` fix(workbench): Bug H (2016) — LXC-Ping-Fehler praeziser.

## 2026-10-05

- `a83f344` fix(workbench): 2015 — ToolArgumentValueError, Nutzereingabe-Fehler 4xx statt 5xx.
- `df72a00` fix(workbench): Bug E + 2013 — ping IPv4 + generischer Fallback-Renderer.
- `a658383` fix(workbench): 2010 + 2012 — network_interfaces Fallback + Merkposten UX.
- `e50618e` fix(workbench): 2009 — Typkonvertierung args in der Route.
- `43b6eb2` docs(workbench): 2002-2006 — Doku-Nachschaerfung Werkbank.
- `0704684` feat(workbench): 1992 — Werkbank-UI (Template, Sidebar, JS, Flags).
- `8e27bdb` feat(workbench): 2000 + 2001 — dns_lookup scope_guard + ToolRunAuditError + UI-Vorbereitung.
- `cffc967` docs(review-log): 1998 — Detailseiten-Aktionen Runde 2.
- `4a341b5` feat(workbench): 1991 — Route /tools + /api/tools/run + Tests.

## 2026-10-04

- `cd18b23` feat(tool-run): 1996 — original_args fuer Audit-Hash.
- Architektur-Doku-Block (Dateien 1-6): Admin-AI-Scope,
  ARCHITECTURE, DESIGN_DECISIONS, PHASES, SECURITY_REVIEW_LOG,
  CONTEXT_PROMPT.
- Punkt 58 Schritte 1-5 (Fundament, ToolRunService, 17 Tools).

## Aelterer Verlauf

Die vollstaendige Historie steht in `git log`.
Sicherheits-Entscheidungen sind in `docs/SECURITY_LOG.md`,
Design-Entscheidungen in `docs/DECISIONS.md`,
Phasen in `docs/ROADMAP.md`.
