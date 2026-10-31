# ADR-0003: Test-Ebenen

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §3

---

## 3. Test-Ebenen

### Ebene 1 — Score-Regeln (tests/unit/test_risk.py)

Prueft konkrete Werte direkt:
base 0.5 + hauptnetz 0.2 + first_seen 0.15 = 0.85 -> CONFIRMED.

Aenderungen an rules.yaml brechen genau diese Tests.

### Ebene 2 — Kategorie -> Severity (tests/unit/test_planning.py)

Prueft das Mapping isoliert:
CONFIRMED -> CRITICAL, SECURITY_ALERT -> WARNING.

Kein Orchestrator, keine Detection.

### Ebene 3 — Kette (tests/integration/test_orchestrator.py)

Prueft Event -> Detection -> Risk -> Loop -> Tool. Severity
wird aus der Assessment-Kategorie ABGELEITET, nicht
hartkodiert:

    CATEGORY_TO_SEVERITY = {
        "EVENT": "INFO",
        "ANOMALY": "INFO",
        "SUSPICION": "WARNING",
        "SECURITY_ALERT": "WARNING",
        "CONFIRMED": "CRITICAL",
    }
    assessment = result.assessments[0]
    expected_severity = CATEGORY_TO_SEVERITY[assessment.category.value]
    assert mock_calls[0]["severity"] == expected_severity

Begruendung: Wenn sich Score-Regeln aendern, bricht nur Ebene 1.
Die Integrationstests bleiben stabil.

---

### Ebene 4 — Approval (tests/unit/test_approval_notify.py, tests/unit/test_approvals_cli.py)

- `test_approval_notify.py`: Hook isoliert, `telegram_alert_run`
  gemockt. 6 Faelle (disabled, status!=APPROVAL, ohne id, mit id,
  Telegram-Fehler, Audit bei Erfolg).
- `test_approvals_cli.py`: CLI mit tmp-SQLite-Datei (Migration
  laeuft). 11 Faelle.
- Integrationstest (spaeter, separat): in
  `tests/integration/test_orchestrator.py` als eigener Test
  (Alert + Approval = zwei Telegram-Nachrichten).

### Ebene 5 — Change Requests (tests/unit/test_changes.py, tests/unit/test_change_applier.py)

- `test_changes.py`: Parser (14), Repository (10), CLI (11).
  Parser-Roundtrip (`to_dict` -> `from_dict`), Zustandsfluss,
  CLI-Export, Audit-Kinds `change_*`.
- `test_change_applier.py`: Applier-Stub wirft
  `NotImplementedError`; `orchestrator.create_change_request`
  legt DRAFT an, Audit `change_created`.
- Integrationstest (spaeter): CLI + Applier + Audit in einer
  Kette, sobald der Applier echt ist.

### Namenskonvention fuer Tests

Verbindlich (siehe auch WORKFLOW.md Abschnitt
"Test-Konventionen (verbindlich)"):

- Klassen mit `*Tests`-Suffix erben von
  `unittest.TestCase`. Ohne Vererbung sammelt pytest
  sie nicht (Default `python_classes = Test*`).
- Alternativ: modulweite `def test_`-Funktionen
  (pytest-Standard).
- Klassen mit `Test*`-Praefix und ohne
  `unittest.TestCase` sind zulaessig, aber kein
  Mischstil in derselben Datei.
- Kein Wechsel ohne Doku-Block.

Beispiel: 3.6.14 `tests/unit/test_filters.py`. Erste
Version hatte Klassen mit `*Tests`-Suffix ohne
`unittest.TestCase`. `py_compile=OK`, aber
`pytest --collect-only -q` lieferte 0. Fix:
Vererbung ergaenzt.
