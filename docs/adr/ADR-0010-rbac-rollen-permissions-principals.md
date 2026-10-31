# ADR-0010: RBAC (Rollen, Permissions, Principals)

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §10

---

## 10. RBAC (Rollen, Permissions, Principals)

### Grundmodell

Drei Entitaeten in SQLite (Migration 0005):

- permissions: feingranulare Codes (chat.ask, approval.decide, ...).
- roles: benannte Rollen (admin, operator, viewer, system).
- role_permissions: n:m zwischen Rollen und Permissions.
- principals: alles, was authentifiziert werden kann.

### Principal statt User

"Principal" ist der Fachbegriff fuer eine Entitaet, die
authentifiziert werden kann. Nicht nur Menschen.

kind:
- human   — Mensch
- system  — interne Komponente (security_ai, host_scanner)
- service — externer Service (admin_ai, api_client)

password_hash NULL = kein Login (z. B. cli-admin).
is_active False = gesperrt.

### Permissions (Phase 3.5)

chat.ask, chat.detail, chat.include_details,
device.read, device.write,
approval.view, approval.decide,
change.view, change.create, change.decide, change.deploy,
audit.read, audit.write,
principal.manage, role.manage

### Rollen und Zuordnung

- admin    -> alle
- operator -> chat.*, device.read, approval.view, approval.decide,
              change.view, change.create, change.decide, audit.read
- viewer   -> chat.ask, device.read, audit.read
- system   -> chat.ask, device.read, audit.write

### Web-Login-Regel (Punkt 3, 2026-09-27)

Ein Principal, der sich einloggen koennen soll,
braucht eine Rolle mit `device.read`.
`AccessService.create_principal` erzwingt das und
wirft `AccessServiceError` bei Rollen ohne
`device.read`.

Fail-closed-Zeitpunkt verschoben: vom Login (spaet)
zum Anlegen (frueh). Rollen ohne `device.read`
bleiben fuer Nicht-Login-Zwecke zulaessig
(z. B. Service-Rollen).

### Chat-Rate-Limit-Store (Punkt 9, c4a1fa0)

RateLimitService nutzt SQLite (chat_rate_hits),
Multi-Worker-fest und Fail closed bei Fehler.
Login-Rate-Limit bleibt getrennt in login_attempts.

### Fail closed

- AccessChecker.has_permission -> False bei jedem Fehler
  (Principal unbekannt, inaktiv, Permission-Code unbekannt).
- AccessChecker.require_permission -> AccessDeniedError.
- Kein Wildcard, kein Prefix-Match. Nur exakte Codes.
- require_permission bleibt im Checker: er ist die zustaendige
  Stelle fuer "darf nicht". Ein Aufrufer, der selbst raise
  macht, wird vergessen, es zu tun. Der Checker nicht.

### Passwort-Hashing (Phase 3.6)

- pbkdf2_sha256, 600_000 Iterationen (OWASP 2023).
- Format: pbkdf2_sha256$600000$<salt_hex>$<hash_hex>.
- In Phase 3.5 noch nicht genutzt: cli-admin laeuft ohne Login.
- Passwort-Login kommt mit dem Web-Dashboard.
