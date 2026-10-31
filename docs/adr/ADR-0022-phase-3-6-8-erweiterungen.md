# ADR-0022: Phase-3.6.8-Erweiterungen

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §22

---

## 22. Phase-3.6.8-Erweiterungen

Siehe auch:
- docs/SECURITY_LOG.md — Sicherheits-
  Entscheidungen nach Thema + offene Punkte 1-11.
- docs/INCONSISTENCIES_FOUND.md — Ausgelagerte
  Inkonsistenzen (heute leer).

Diese Eintraege sind aus 3.6.8d-i entstanden und hier
zusammengefasst (kein eigener § pro Entscheidung, weil
sie sich direkt aus § 11 und § 16 ableiten).

### ServiceError / OperationError

Siehe § 11.

### ChangeService

- core/services/change_service.py.
- RBAC: change.view fuer Lesen, change.create fuer
  Anlegen.
- Audit-Kind: change_created (TOOL=change_service).
- Laengengrenzen als Modul-Konstanten (TITLE_MAX=200,
  DESCRIPTION_MAX=2000, DIFF_MAX=20000, ROLLBACK_MAX=2000,
  TEST_PLAN_MAX=2000, FILES_MAX_ENTRIES=50, FILE_PATH_MAX=500).
- Audit-Felder bei create: change_id, type, title
  (max 100), requested_by. KEIN description, diff_or_patch,
  rollback_plan, test_plan, files_affected.

### RateLimitService

- core/services/rate_limit_service.py.
- In-Memory, threading.Lock, Key = principal_name.
- WINDOW_SECONDS=60, MAX_REQUESTS=10.
- 429 + Retry-After.
- Kein Audit/Log bei Treffer.
- Single-Process heute; Multi-Worker -> gemeinsamer
  Store (Redis/DB).

### View-Projektionen (core/access/models.py)

Explizite, oeffentliche Funktionen statt Modell-to_dict:

- principal_to_view(principal) -> dict
    name, kind, role_id, is_active, has_password,
    created_at. Kein password_hash, kein row_id.
- role_to_view(role) -> dict
    name, description, created_at, permissions (sortiert).
- permission_to_view(permission) -> dict
    code, description. Kein row_id.

Begruendung: Ein Modell-to_dict wuerde reflexhaft alle
Felder mitliefern und irgendwann password_hash. Die
View-Funktion ist explizit und auditierbar.

### MIN_PASSWORD_LEN

- core/services/access_service.py, MIN_PASSWORD_LEN = 12.
- set_password prueft Laenge VOR der DB-Abfrage
  (fail closed auf Format, kein Existenz-Oracle).
- create_principal nimmt kein password_hash mehr;
  Passwort setzen ist ein eigener Schritt (set_password).

### _inject_csrf-Context-Processor

- apps/dashboard/app.py, zweiter context_processor.
- Liefert csrf_token in jedes Template.
- get_or_create ist idempotent (rotiert nicht pro
  Request); Rotation nur nach Login.
- base.html <body data-csrf-token="{{ csrf_token }}">.
- JSON-Endpoints (/api/chat) nutzen Header
  X-CSRF-Token statt Form-Feld.

### list_roles RBAC (3.6.8f)

- list_roles: role.manage ODER principal.manage.
- Begruendung: Principals anlegen erfordert
  Rollen-Kenntnis.
