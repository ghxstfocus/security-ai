# ADR-0000: Guardrails (Phase 18)

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §0

---

## 0. Guardrails (Phase 18)

Guardrails sind Regeln mit Level und State (enabled/disabled), die im Dashboard verwaltet werden.

- Speicherung in SQLite (data/migrations/0016_guardrails.sql).
- Konfiguration in core/guardrails/guardrails.yaml.
- RBAC: guardrail.view (lesen), guardrail.manage (schreiben).
- State-Wechsel erzeugt Audit-Eintrag kind='guardrail_state_changed'.
- Dashboard-Route /guardrails (read-only) und POST /api/guardrails/<id>/state.

---
