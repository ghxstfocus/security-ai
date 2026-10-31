# ADR-0026: Ollama-Rueckbau (beschlossen)

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §26

---

## 26. Ollama-Rueckbau (beschlossen)

Der lokale Ollama-Chat wird entfernt. Grund:
das lokale Modell (llama3.2:3b, qwen2.5:7b)
liefert keine brauchbaren Antworten fuer die
Komplexitaet der Aufgaben, die das System
bewaeltigen soll.

Die Intelligenz-Schicht wird von Cloud-Providern
uebernommen (siehe § 28). Der lokale Chat,
die Frage-Klassifikation (§ 14), der Auto-
Switch (§ 12) und die zugehoerigen
Komponenten (ChatService, chat_cli, Dashboard-
Chat, Kontext-Bauer, Chat-Links,
Wert-Synonyme) werden entfernt.

Das Dashboard bleibt als Basic-Verwaltung
ohne LLM. Guardrails-Aktivierung ist
Mensch-only (ueber Dashboard oder CLI).

Siehe SECURITY_REVIEW_LOG Punkt 88.
