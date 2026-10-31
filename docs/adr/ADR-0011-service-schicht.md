# ADR-0011: Service-Schicht

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §11

---

## 11. Service-Schicht

### Drei Schichten

1. UI (Web Flask, CLI, Telegram) — ruft nur Services.
2. Service-Schicht (core/services/) — Fachlogik,
   Berechtigungspruefung, Audit.
3. Repositories (core/access, core/approval, core/changes,
   core/inventory) — DB-Zugriff.

### Beispiel

    AccessService.create_principal(actor, name, role_name, ...):
        - Berechtigung pruefen (principal.manage)
        - Validierung
        - repo.create(...)
        - audit.log(principal_created)

Web-Route, CLI und Telegram rufen denselben Service. Keine
Fachlogik in der UI.

### Audit ist Pflicht in der Service-Schicht

- Jede schreibende Service-Methode ruft audit.log(...).
- details.kind ist die Aktion (z. B. principal_created,
  permission_assigned).
- Fehlt der AuditWriter, wirft der Service (fail closed).

### Fehlerklassen in der Service-Schicht (3.6.8d)

Seit 3.6.8d gibt es zwei Basis-Fehlerklassen in
core/services/errors.py:

- ServiceError    = fachlicher/Format-Fehler -> 4xx
                    Ungueltige Eingabe, fehlende
                    Pflichtfelder, Formatfehler.
- OperationError  = Betriebsfehler -> 5xx
                    DB-Fehler, Audit-Fehler,
                    unerwartete Laufzeitfehler.

OperationError ist bewusst NICHT Subklasse von
ServiceError, damit ein `except ServiceError` im
Route-Handler den Betriebsfehler NICHT faengt und der
globale 500-Handler greifen kann.

Regel: Format-Fehler -> ServiceError-Subklasse -> 4xx.
       Betriebs-Fehler -> OperationError-Subklasse -> 5xx.

Vorbild: ChangeService (3.6.8d) mit ChangeServiceError
(ServiceError) und ChangeOperationError (OperationError).

Stand 3.6.15c: Alle vier Kern-Services haben jetzt die
Trennung:
- ChatService:        ChatServiceError (ServiceError) /
                      ChatOperationError (OperationError).
                      LLMError/LLMTimeout/LLMUnavailable
                      bleiben roh (502 Upstream).
- ApprovalService:    ApprovalServiceError (ServiceError) /
                      Repo-Fehler propagieren (Variante D,
                      siehe Regel unten).
- InventoryService:   InventoryServiceError (ServiceError) /
                      InventoryOperationError (OperationError).
- AuditReaderService: AuditReaderServiceError (ServiceError) /
                      AuditReaderOperationError (OperationError).

Regel (3.6.15c, Auflage 506): Repo-Fehler mit semantischer
Bedeutung (NotFound, State) werden nicht in ServiceError
gewickelt. Die Route behandelt sie direkt:
  ApprovalNotFoundError -> 404.
  ApprovalStateError    -> 409.
Die Basisklasse ApprovalRepositoryError wird NICHT
gefangen -> globaler 500.
LLM-Fehler werden nicht in OperationError gewickelt.
Sie haben eigene Semantik (502 Upstream).

### Wert-Synonyme fuer die Suche (Punkt 29)

Suchbegriffe werden auf Synonym-Zielwerte erweitert
(core/search/synonyms.yaml + synonyms.py).
Beispiel: "alarm" -> category=SECURITY_ALERT.
Nur Werte, nicht Quellen. Die normale String-Suche
bleibt zusaetzlich. Dedup pro Quelle (Audit-ID,
Request-ID, Change-ID). Kein Regex, kein Stemming.

### Suchfelder pro Quelle (Auflage 530, 3.6.16)

Suchfelder pro Quelle werden in Auflage 530 (3.6.16)
definiert. Bei jeder Aenderung an einer Quelle pruefen,
ob ein Feld ergaenzt oder entfernt werden muss.
Stand 3.6.18a: category bei risk_assessments ergaenzt.

### Kontext-Aufbau fuer den Chat (Punkt 28)

Der Kontext fuer ChatService.ask liegt in
core/context/builder.build_chat_context.
Kein RBAC, kein Audit. Wird von CLI
(scripts/chat_cli.py) und Dashboard
(apps/dashboard/routes_chat.py) genutzt.
Log-Excerpts und recent_events sind leer
(Auflagen 720/721).

### ChatService — entfernt (Phase 16)

Der ChatService (apps/security_ai/chat.py) und
der zugehoerige Kontext-Bauer wurden mit dem
Ollama-Rueckbau (Phase 16) entfernt. Die
Intelligenz-Schicht wird von der Admin AI
uebernommen (siehe docs/ADMIN_AI_SCOPE.md).

Die nachfolgende Beschreibung bleibt als
historischer Bezug stehen. Sie ist nicht mehr
aktiv.


- Nutzt AccessChecker (RBAC).
- Nutzt ContextBuilder (harness/context).
- Nutzt LLMClient (harness/llm).
- LLM entscheidet nichts. Der Service ruft nur das LLM, um
  eine Antwort zu formulieren.
- Fail closed bei RBAC UND bei LLM-Fehler: LLMError wird
  propagiert. Ein Chat, der eine erfundene Antwort liefert,
  ist schlimmer als einer, der "nicht erreichbar" sagt.

### Audit-Kinds (Phase 3.5, Chat)

- chat_query          (immer, vor RBAC)
- chat_access_denied  (bei RBAC-Verweigerung: chat.ask,
                       chat.include_details, chat.detail)
- chat_answered       (bei erfolgreicher Antwort)
- chat_llm_error      (bei LLM-Fehler)

Die Frage selbst landet NICHT im Audit. Stattdessen:
- question_hash (sha256, 64 Hex)
- question_hash_short (erste 16 Hex)

### Detail-Anhang ohne LLM

Wenn die Frage nach einer IP fragt (Regex) oder detail=True
gesetzt ist, wird der Detail-Pfad genutzt:
- kein LLM-Aufruf,
- Antwort direkt aus dem Kontext (Event-Identifier +
  inventory.recently_added + recently_offline),
- Dedup via set, sortierte Ausgabe,
- braucht die Permission chat.detail.

### Modellwahl

- Default: llama3.2:3b (schnell, CPU-tauglich).
- Large: qwen2.5:7b (langsam, tiefere Fragen).
- Konfiguration in .env: OLLAMA_BASE_URL,
  SECURITY_AI_MODEL, SECURITY_AI_MODEL_LARGE.
- Der Client bleibt dumm: Modell ist Parameter mit Default
  aus harness.llm.models. ChatService liest den Default
  aus core.config.

### Was Phase 3.5 NICHT macht

- Kein Web-Dashboard (Phase 3.6).
- Kein Login (Phase 3.6).
- Kein Streaming (spaeter).
- Keine Session-Historie (harness/memory, spaeter).
