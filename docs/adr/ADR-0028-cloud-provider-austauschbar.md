# ADR-0028: Cloud-Provider austauschbar

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §28

---

## 28. Cloud-Provider austauschbar

Die LLM-Anbieter sind austauschbare Module.
Der Core kennt nur das LLMProvider-Interface.
Welche Anbieter konfiguriert sind, steht in
einer Provider-Registry.

Vorgesehene Anbieter (nicht abschliessend):
- Azure OpenAI (deutscher Standard fuer
  Firmen).
- Anthropic (Claude).
- OpenAI (GPT).
- DeepSeek.
- Microsoft Copilot.

Ein neuer Anbieter ist ein Eintrag in der
Provider-Registry und eine Implementierung
des LLMProvider-Interface. Kein Umbau der
Architektur.

Der Core routet Anfragen an den passenden
Provider je nach:
- Datenklassifikation (§ 27),
- Verfuegbarkeit,
- Konfiguration.
