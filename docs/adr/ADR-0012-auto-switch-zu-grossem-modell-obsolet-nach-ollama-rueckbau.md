# ADR-0012: Auto-Switch zu grossem Modell — obsolet nach Ollama-Rueckbau

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §12

---

## 12. Auto-Switch zu grossem Modell — obsolet nach Ollama-Rueckbau

Begruendung: das lokale 3B-Modell liefert
keine brauchbaren Antworten fuer die Komplexitaet
der Aufgaben. Ersetzt durch Cloud-Provider
(siehe docs/ADMIN_AI_SCOPE.md, Phase 13, und
SECURITY_REVIEW_LOG Punkt 88).

(Historischer Inhalt, nicht mehr aktiv.)

--- Ab hier: der bisherige § 12-Inhalt ---

### Prinzip

Zustandsfragen mit kritischen Assessments werden mit dem
grossen Modell beantwortet (qwen2.5:7b). Alle anderen Fragen
mit dem Default (llama3.2:3b).

Grund: Das 3B-Modell erkennt zwar die Zahlen, interpretiert
sie aber falsch ("keine Auffaelligkeiten" bei 31 CONFIRMED).
Das 7B-Modell beantwortet dieselbe Frage korrekt, ist auf
CPU-only aber deutlich langsamer (1-3 Minuten).

### Regel

    if explicit_model:
        -> explicit_user
    elif auto_large and is_critical_state_question:
        -> auto_critical_state
    else:
        -> default

Kritisch = _is_state_question(question) UND
           risk_assessments enthaelt CONFIRMED oder
           SECURITY_ALERT.

auto_large ist Default True, per --no-auto-large oder
ChatService(auto_large=False) abschaltbar. Aber:
- Fakt-Fragen gehen nie ans LLM (Abschnitt 14).
- Concept-Fragen ignorieren den Auto-Switch (Abschnitt 14).
- Der Sanity-Check bleibt unabhaengig von auto_large aktiv.

### Timeouts

Modellabhaengig:

    llama3.2:3b  -> 30 s
    qwen2.5:7b   -> 180 s
    unbekannt    -> 60 s

--timeout ueberschreibt.

### Transparenz

ChatResponse.model_reason: "default" | "auto_critical_state" |
"explicit_user".

CLI zeigt:

    [Modell: qwen2.5:7b -- auto_critical_state]
    [Auto-Switch zu grossem Modell -- kann 1-3 Minuten dauern]

### Audit

chat_answered enthaelt model und model_reason. Damit ist
nachvollziehbar, welches Modell mit welcher Begruendung
geantwortet hat.

### Auto-Switch ist PFLICHT bei kritischen Assessments

llama3.2:3b ist bei kritischen Assessments unzuverlaessig.
Zwei Live-Tests haben das gezeigt:

1. Phase 3.5.7: Antwort "NEIN, keine Auffaelligkeiten"
   trotz 31 CONFIRMED + 12 SECURITY_ALERT im Kontext.
2. Phase 3.5.9: Antwort "7 SUSPICION-Auffaelligkeiten"
   trotz 31 CONFIRMED (Underreporting).

Beide Faelle sind kein Prompt-Problem. Ein 3B-Modell kann
nicht zuverlaessig schliessen.

Konsequenz:

- Auto-Switch zu qwen2.5:7b bei Interpretation mit kritischen
  Assessments ist PFLICHT, nicht Robustheit.
- --no-auto-large riskiert Underreporting. CLI-Warnung.
- Der Sanity-Check (Denial + Underreporting) ist NICHT durch
  auto_large abschaltbar. Sicherheitsschicht.
- Der Sanity-Check greift nur bei Interpretation, nicht bei
  concept (Konzeptfragen reden nicht ueber den Kontext).

### Abgrenzung zu Fakt-Fragen

Faktenfragen ("Gab es Auffaelligkeiten?", "Wie viele Events?")
laufen NICHT ans LLM. Sie sind deterministisch (Abschnitt 14).
Der Auto-Switch ist nur fuer Interpretationsfragen relevant.

### Modellwahl bleibt Empfehlung (nur bei Interpretation)

Wenn keine kritischen Assessments vorliegen, ist die
Modellwahl eine Empfehlung. Der Mensch kann mit --model
eingreifen. Bei kritischen Assessments greift die Pflicht.
