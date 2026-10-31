# ADR-0023: Alarm-Kanal

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §23

---

## 23. Alarm-Kanal

Der Alarm-Pfad und der Approval-Pfad nutzen
getrennte Kanaele.

### Alarm-Pfad (Punkt 81)

- Primaerer Kanal: ntfy (self-hosted, Tailscale).
- planning.py liefert PlanStep tool="notify_ntfy".
- Tool registriert in apps/security_ai/orchestrator.py
  _build_default_registry (NMAP_SCAN, READ_LOGS,
  GET_DEVICES, WHITELIST_CHECK, TELEGRAM_ALERT,
  NOTIFY_NTFY).
- Level 1 (Security Action), Sandbox-Profil
  no_network_except_ntfy.
- Fallback-Kette ntfy -> Telegram (spaeterer Ausbau).

### Approval-Pfad (Paragraph 9, unveraendert)

- orchestrator._notify_approval ruft telegram_alert_run
  DIREKT auf, NICHT ueber die Registry.
- config.yaml approval_notify.channel bleibt
  "telegram".
- Eigener Punkt 81a, falls Approval-Notify spaeter
  auch auf ntfy soll.

### Telegram bleibt optional (Punkt 76)

- telegram_alert bleibt als Tool registriert.
- Kann durch Fallback-Kette oder manuelle Konfig
  genutzt werden.
