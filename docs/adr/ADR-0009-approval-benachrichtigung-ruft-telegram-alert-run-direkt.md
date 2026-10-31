# ADR-0009: Approval-Benachrichtigung ruft telegram_alert_run direkt

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §9

---

## 9. Approval-Benachrichtigung ruft telegram_alert_run direkt

_notify_approval ruft telegram_alert_run DIREKT auf —
nicht ueber die Tool Registry, nicht ueber den Agent Loop.

### Begruendung

- Es ist eine Benachrichtigung, keine Aktion. Wie ein
  Log-Eintrag, nur ueber einen anderen Kanal.
- Keine Policy dafuer: "Darf ich eine Approval-
  Benachrichtigung schicken?" ist eine Betriebsfrage, keine
  Sicherheitsfrage.
- Kein Approval fuer eine Approval-Benachrichtigung
  (rekursiv).
- Die DB ist die Quelle der Wahrheit. Die Benachrichtigung
  ist best effort. Wenn sie fehlschlaegt, ruft der Mensch
  die CLI auf.

### Konsequenz

- _notify_approval faengt Telegram-Fehler ab, propagiert
  sie nicht.
- Audit-Kinds: approval_notify_sent,
  approval_notify_failed, approval_notify_skipped.
- enabled=False -> no-op + Audit approval_notify_skipped.

Der normale Alarm-Pfad (ueber Agent Loop) bleibt
unveraendert.

### Abgrenzung

- Alarm-Pfad (Agent Loop, Tool Registry, Policy, Audit
  tool_call): unveraendert.
- Approval-Anlage selbst laeuft ueber die DB
  (ApprovalQueue.enqueue), nicht ueber die Registry.
- Approval-Benachrichtigung ist der einzige Pfad, der
  telegram_alert_run direkt ruft.
