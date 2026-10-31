# ADR-0001: Design-Entscheidungen

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §1

---

## 1. Design-Entscheidungen

### 1. Input-/Output-Event-Typen strikt getrennt

- connection_attempt / syn_packet -> PORT_SCAN
- device_presence / device_offline -> UNKNOWN_DEVICE

Keine Regel triggert auf ihr eigenes Output-Event.

Begruendung: Sonst Endlosschleifen und unklare Verantwortung.

### 2. State im RuleContext, nicht im Regel-Objekt

Regeln sind zustandslos. Zustand (Ringpuffer fuer port_scan)
liegt in RuleContext.state, thread-sicher und resetbar.

Begruendung: Spaetere Auslagerung in Redis/DB moeglich, ohne
Regeln anzufassen. Keine Multi-Threading-Probleme.

### 3. DB nur im Orchestrator

Detection und Risk sind DB-frei. Der Orchestrator liest
Snapshots und reicht sie als Kontext durch.

Begruendung: Determinismus, Testbarkeit, klare Verantwortung.

### 4. Inventory-Update VOR Detection/Risk

Ein device_presence-Event wird erst ins Inventory geschrieben,
dann durch Detection/Risk bewertet.

Der not_in_inventory-Bonus greift NICHT beim allerersten
Auftreten. Stattdessen setzt der Orchestrator
first_seen=True/False in den Alert (Pre-Snapshot-Vergleich),
und der Risk-Pruefer first_seen greift darauf.

Begruendung: Risk Engine sieht aktuellen Zustand. Ein frisch
angelegtes Geraet ist "in_inventory", aber nicht "known".

### 5. Append-only History

device_history.event_type ist frei (kein CHECK). Konventionen:
- device_seen
- device_offline
- whitelist_added
- whitelist_removed

data_json ist schema-los (freies JSON).

Begruendung: Neue Event-Typen ohne Migration. Die Konvention
steht im Code, nicht in der DB.

### 6. Whitelist als eigene Tabelle

whitelisted_devices ist die einzige Quelle fuer "wer ist
erlaubt". Kein is_whitelisted-Feld in devices.

Begruendung: Zwei Quellen der Wahrheit fuehren zu Bugs.

### 7. Risk Engine deterministisch, kein LLM

base + add-Modifier, auditierbar. Kein Multiplikator, keine
Konditional-Logik (fuer jetzt).

Begruendung: Scores muessen reproduzierbar und nachvollziehbar
sein. Das LLM erklaert spaeter nur.

### 8. Fail closed

- Unbekannter when-Name -> RiskRuleError
- Fehlender default-Block in rules.yaml -> RiskRuleError
- Fehlende Predicate-Felder -> False (fail safe)

Begruendung: Kein stiller Durchlauf bei Konfigurationsfehlern.

### 9. Alert-Events erben event.timestamp

Der Alert beschreibt das Ereignis, nicht den Erkennungszeitpunkt.
RiskAssessment.timestamp = Bewertungszeitpunkt.

Begruendung: Risk Engine prueft nachts/wochenende gegen den
Vorfall, nicht gegen jetzt.

### 10. Frischer Inventory-Snapshot pro process()-Call

Alle Alerts eines Events sehen denselben Zustand. Nicht pro
Alert ein eigener Snapshot.

Begruendung: Determinismus pro Verarbeitungsschritt.

### 11. base + add ohne Multiplikatoren

Reicht fuer Phase 2b. rules.yaml-Schema soll spaeter
multiply: und condition: aufnehmen koennen (noch nicht
implementiert).

Begruendung: Erst stabilisieren, dann erweitern.

### 12. Prioritaet in port_scan._classify

port_scan > network_scan > brute_force.

Begruendung: Deterministische Klassifikation. brute_force ist
eigenstaendig und kann parallel auftreten — spaeter mehrere
Output-Events pro Regel.

### 13. AgentLoop ist stateless

policy_context wird pro run(event, policy_context=...) uebergeben,
nicht im Konstruktor gehalten.

Begruendung: Determinismus, keine Zustandslecks zwischen Events.

### 14. Globale vs. spezifische Policy-Pruefer

GLOBAL_PREDICATES (no_shell_chars, no_path_traversal,
no_null_bytes) laufen IMMER, unabhaengig von der Policy.
SPECIFIC_PREDICATES (authorized_target, read_only_path,
target_in_scope) laufen nur via conditions.

Begruendung: Sicherheitspruefer, die vergessen werden koennen,
sind keine Sicherheitspruefer.

### 15. Strengste Entscheidung gewinnt

FORBIDDEN > APPROVAL_REQUIRED > ALLOWED.

Weiche Pruefer (on_fail=APPROVAL_REQUIRED): Mensch kann
freigeben. Harte Pruefer (on_fail=FORBIDDEN): sofort blockiert.

Begruendung: Kein stiller Durchlauf bei Konflikten.

### 16. Kein eval, kein DSL in der Policy Engine

Pruefer-Namen in YAML, Implementierung in Python. Unbekannter
Name -> PolicyError beim Laden.

Begruendung: Deterministisch, auditierbar, keine
Injection-Angriffsflaeche.

### 17. Tools: func(**args), kein Context

Der AgentLoop ruft Tools mit Keyword-Argumenten auf. Tools
bleiben kontextfrei.

Begruendung: Testbar, deterministisch, keine implizite
Abhaengigkeit auf Umgebung.

### 18. source-Marker statt mock-Feld

Jedes Tool-Ergebnis traegt "source": "mock" | "db" | "nmap" |
"telegram" | ... Kein separates "mock"-Feld.

Begruendung: Eine Konvention, ein Marker. Werte wechseln, wenn
echte Ausfuehrung dazukommt.

### 19. Fail closed bei fehlender DB

get_devices und whitelist_check werfen ToolError, wenn die DB
fehlt. Kein stilles leeres Ergebnis.

Begruendung: Ein Tool, das stillschweigend leer liefert, ist
eine Sicherheitsluecke.

### 20. AgentLoop Policy-Check VOR Argument-Validierung

Reihenfolge im Loop:
Tool-Lookup -> Permission -> Level-4-Approval -> Policy
-> Argument-Validierung -> Ausfuehrung.

Begruendung: Policy kann Tools verbieten, unabhaengig von
Argumenten.

### 21. Service-interne RBAC-Helfer parametrisiert

Service-interne RBAC-Helfer nehmen den Permission-Code
als Parameter, nicht fest verdrahtet. Beispiel:

    def _require(self, actor, code):
        self._checker.require_permission(actor, code)

Aufrufstellen nennen den Code explizit:

    self._require(actor, "audit.read")
    self._require(actor, "alert.view")

Grund: eine Methode fuer mehrere Permissions, Code an
der Aufrufstelle sichtbar. Kein Helper pro Permission.

---
