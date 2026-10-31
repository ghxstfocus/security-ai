# ADR-0015: Redaction / Prompt-Injection-Schutz (Phase 3.5)

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §15

---

## 15. Redaction / Prompt-Injection-Schutz (Phase 3.5)

> Hinweis (2026-10-04): Redaction wird fuer
> Cloud-LLM weiter genutzt — sogar wichtiger,
> weil Cloud bedeutet, dass Daten das Haus
> verlassen. Der folgende Abschnitt beschreibt
> Regeln, die weiterhin gelten.

### Prinzip

Rohdaten (Events, Logs, DB-Felder) werden gefiltert, bevor
sie ans LLM gehen. Das LLM sieht nur, was der Kontext-Bauer
freigibt.

Modul: `harness/context/redaction.py`.

### Regeln

- Steuerzeichen entfernen: \x00, \r, \x0b, \x0c.
  (\t und \n bleiben, mehrzeilige Logs sind erlaubt.)
- Instruktions-Marker entfernen (case-insensitive):
  "ignore previous", "ignore all", "ignore the above",
  "system:", "assistant:", "user:",
  "<|im_start|>", "<|im_end|>", "###instruction",
  "[inst]", "[/inst]", "<<sys>>", "<</sys>>".
- Laenge begrenzen: Default 2000 Zeichen, dann [REDACTED].
- Bei Verstoss: Passage durch [REDACTED] ersetzen.

### API

- redact_text(text, max_len) -> (str, bool)
- redact_field(value, max_len) -> (str, bool)
- redact_mapping(dict, max_len) -> (dict, bool)

Fail closed: Nicht-String -> ("", True) (markiert als
redigiert).

### ContextBundle.redacted

Der Kontext-Bauer setzt `redacted=True`, sobald mindestens
eine Redaktion stattfand. Der Chat-Prompt weist das Modell
darauf hin.

### Was NICHT gefiltert wird

- Risk-Assessments (strukturierte Objekte, kein Freitext).
- Approvals, Changes (strukturierte Objekte).
- Inventory-Snapshot (Aggregate).

Nur Freitext (Log-Ausschnitte, Feld-Werte) wird redigiert.

### Audit

Redaction selbst wird nicht auditiert (Performance). Der
redacted-Flag im Kontext ist ausreichend. Wenn im Prompt
`- Hinweis: Kontext wurde redigiert.` steht, weiss der
Nutzer, dass Redaktion stattfand.

### Abgrenzung zu Sanity-Check (§ 14)

- Redaction: schuetzt vor Injection **vom Kontext ins LLM**.
- Sanity-Check: schuetzt vor falschen **Antworten des LLM**
  (Denial, Underreporting).
