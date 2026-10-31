# ADR-0014: Frage-Klassifikation — obsolet nach Ollama-Rueckbau

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §14

---

## 14. Frage-Klassifikation — obsolet nach Ollama-Rueckbau

Begruendung: die Klassifikation war fuer das
lokale Modell gedacht. Cloud-Provider
uebernehmen die Klassifikation selbst. Siehe
docs/ADMIN_AI_SCOPE.md, Phase 13, und
SECURITY_REVIEW_LOG Punkt 88.

(Historischer Inhalt, nicht mehr aktiv.)

--- Ab hier: der bisherige § 14-Inhalt ---

### Drei Arten von Fragen

1. fact            -> deterministische Antwort aus context,
                      KEIN LLM-Aufruf.
2. concept         -> LLM (3B), kein Kontext-Zwang.
3. interpretation  -> LLM mit Kontext (7B via Auto-Switch).

### Regex

    _FACT_RE:
        wie viele | wieviele | welche kategorien |
        wie hoch | wie oft | wie lange |
        gab es | gibt es | gibts | gibt's |
        liste | zeig mir

    _CONCEPT_RE:
        was ist | was bedeutet | wie funktioniert |
        erklaere | was sind

    Reihenfolge (3.6.15d, Auflage 513; erweitert um
    Veto, Punkt 32, Auflagen 805-811):
      if _FACT_RE and not _has_critical_state_word(q): fact
      elif _CONCEPT_RE and not _is_state_question: concept
      sonst: interpretation

    Veto (Punkt 32, A805/A806): _has_critical_state_word
    prueft die Frage gegen _CRITICAL_STATE_WORDS. Nur
    Woerter, die eine Bewertung implizieren:
      kritisch, alarm, vorfall, vorfaelle, vorfaellen,
      bestaetigt, confirmed, security_alert,
      security-alert, suspicion, verdacht, warnung,
      warnungen.
    "Auffaellig" ist bewusst NICHT dabei (Sachverhalts-
    frage, kein Bewertungswort). "Status", "Info",
    "Event" sind bewusst NICHT dabei (zu breit).
    _is_state_question bleibt unveraendert (breitere
    Semantik fuer den Auto-Switch); das Veto fuer den
    fact-Pfad ist eine eigene, engere Regel.

    Wichtig (3.6.15d): concept nur, wenn NICHT
    Zustandsfrage. "Was ist heute Nacht passiert?"
    matcht _CONCEPT_RE, ist aber Zustandsfrage und
    muss als interpretation laufen (Kontext + 7B).

Hinweis: "welche IP" ist Detail, NICHT Fact.
Der Detail-Pfad greift VOR dem Fact-Pfad.

### Reihenfolge in ask()

1. chat_query (immer, vor RBAC)
2. RBAC chat.ask
3. Detail-Pfad (Detail-Regex ODER --detail Flag)
4. Fact-Pfad (_FACT_RE, context.has_data())
5. no_context-Pfad (Interpretation + Zustandsfrage ohne Kontext)
6. Concept-Pfad (_CONCEPT_RE, LLM mit default_model)
7. Interpretation-Pfad (LLM, Auto-Switch bei kritisch)

### source-Werte

- "detail_append"  Detail
- "fact"           Faktenantwort
- "no_context"     keine Daten fuer Interpretation
- "llm"            Concept oder Interpretation
- "llm_error"      LLM-Fehler

### Warum das die richtige Architektur ist

Ein LLM darf keine Fakten erfinden. Ein 3B-Modell schliesst
falsch. Ein 7B-Modell ist zu langsam fuer jede Frage.

Konsequenz: Alles, was deterministisch aus dem Kontext
ableitbar ist, wird deterministisch beantwortet. Das LLM
macht nur, was es wirklich kann: formulieren und
interpretieren.

### Auto-Switch-Bedingung (3.6.15d, Auflage 507)

Auto-Switch zu 7B greift bei JEDER Interpretation mit
kritischen Assessments (CONFIRMED, SECURITY_ALERT),
nicht nur bei Zustandsfragen.

Begruendung: Bei 91 kritischen Assessments ist der
Zustand der Welt selbst der kritische Fakt. Wer in
dieser Lage eine Interpretationsfrage stellt, braucht
eine Antwort, die den Zustand beruecksichtigt.
Zustandsfrage-Erkennung per Regex ist nicht mehr
Voraussetzung fuer den Auto-Switch.

Concept-Fragen bleiben 3B ohne Kontext (Auflage 517):
Wer nach der Definition eines Portscans fragt, will
keine Zustandsanalyse.

### --no-auto-large bleibt

Trotz fact-Pfad bleibt --no-auto-large sinnvoll:
- Bei Interpretationsfragen mit kritischen Assessments
  ist 3B unzuverlaessig.
- Der Nutzer kann es bewusst abschalten (Tests, Debugging).

### Sanity-Check (Phase 3.5.9, spaeter)

Wenn interpretation und LLM-Antwort dem Kontext widerspricht:
- Audit chat_answer_contradicts_context.
- Optional Retry mit 7B.

### Anzeige-Labels und Zeitraum im Fact-Pfad (Punkt 31)

Der Fact-Pfad nutzt die Anzeige-Labels aus
core/risk/models.py (CATEGORY_LABELS). Rohkategorien
werden nicht angezeigt (Auflage 829).
Reihenfolge nach Schweregrad absteigend:
CONFIRMED, SECURITY_ALERT, SUSPICION, ANOMALY, EVENT.
Der Begriff "Assessments" wird im Fact-Text durch
"Vorkommen" ersetzt.

ChatService.ask nimmt since_hours (Default 24). Der
Wert fliesst in ContextBundle.since_hours und wird
in _answer_fact zur Anzeige genutzt (Auflage 854).
