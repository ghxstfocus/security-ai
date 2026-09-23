# Web-Security-Checkliste (Phase 3.6)

Verbindliche Checkliste fuer das Web-Dashboard. Jeder Punkt
wird vor Merge geprueft. Bei Abweichung: STOP, Begruendung
im Commit oder im Code-Kommentar.

Wichtig: Die UI ist NIE die Sicherheitsgrenze. RBAC und
Policy greifen im Service-Layer. Das UI darf nur anzeigen,
was der Service freigibt.

## A. Authentifizierung

- [ ] Passwort-Hashing: pbkdf2_sha256, 600_000 Iterationen
      (Format: pbkdf2_sha256$600000$<salt>$<hash>).
- [ ] Vergleich mit hmac.compare_digest (timing-safe).
      (in core/access/models.py::verify_password vorhanden)
- [ ] Kein Klartext-Passwort in Logs oder Audit.
- [ ] Fail closed bei fehlendem password_hash: Systeme
      ohne Login koennen sich NICHT anmelden.
- [ ] Fail closed bei is_active=False.

## B. Sessions

- [ ] Serverseitige Sessions. Kein Cookie mit Nutzdaten.
- [ ] SECRET_KEY aus .env (nicht im Repo). Mind. 32 Byte.
- [ ] Cookie-Flags: HttpOnly, Secure, SameSite=Strict.
- [ ] Session-Timeout (z.B. 30 min idle).
- [ ] Logout invalidiert serverseitig.
- [ ] Login rotiert die Session-ID (Session-Fixation
      verhindern).

## C. CSRF

- [ ] Pflicht fuer POST/PUT/DELETE mit Cookie-Auth.
- [ ] Token-Verfahren: Flask-WTF oder synchronizer token.
- [ ] JSON-Endpoints mit Cookie-Auth ebenfalls schuetzen.
- [ ] Ausnahme nur mit Authorization-Header und
      SameSite=Strict.

## D. RBAC

- [ ] Jede Route ruft AccessChecker.require_permission(
      principal, code).
- [ ] UI-Verstecken von Menuepunkten ist KEIN Schutz.
- [ ] GET-Routen: *.view-Permission.
- [ ] POST/PUT/DELETE: Aktions-Permission.
- [ ] whoami-Route fuer UI-Anzeige, nicht als RBAC-Ersatz.
- [ ] 403 bei fehlender Permission, nicht 404.
      (404 nur, wenn Existenz verbergen gewuenscht.)

## E. XSS

- [ ] Jinja2-Autoescape ist Standard, NICHT mit |safe
      abschalten.
- [ ] Kein Markup(...) aus Nutzereingaben.
- [ ] Chat-Antworten des LLM als Text rendern
      (<pre> mit white-space: pre-wrap), nicht als HTML.
- [ ] Content-Security-Policy-Header:
      default-src 'self'; script-src 'self';
      style-src 'self'; img-src 'self' data:;
      connect-src 'self'.
      (Quelle: DESIGN_DECISIONS §16 — streng, kein
      unsafe-inline, kein unsafe-eval.)
- [ ] Keine Inline-Skripte (nur externe JS-Dateien).

## F. SQL-Injection

- [ ] Nur parametrisierte Queries (?-Platzhalter).
- [ ] Kein String-Concatenation in SQL.
- [ ] Web-Layer ruft NIEMALS direkt SQL.
      Immer ueber Repositories in core/.

## G. Path-Traversal / File-Uploads

- [ ] Kein File-Upload in Phase 3.6.
- [ ] Falls doch noetig: Whitelist der Extensions,
      pathlib.resolve().is_relative_to(BASE) pruefen.
- [ ] Dateien nicht im Web-Root speichern.

## H. LLM im Web-Kontext

- [ ] Chat-Route ruft ChatService.ask(...).
      Der Service macht RBAC + Klassifikation +
      Sanity-Check.
- [ ] Keine direkte LLM-Anbindung in der Route.
- [ ] Chat-Antworten als Text, nicht als HTML.
- [ ] Rate-Limit fuer Chat-Endpoint
      (z.B. 10 Anfragen/Minute pro Principal).
- [ ] Timeout fuer Chat-Requests (180s fuer 7B).

## I. Audit

- [ ] Jeder Login-Versuch wird auditiert:
      login_success, login_failed, login_locked.
- [ ] Login-Audit enthaelt IP + User-Agent
      (nur Nachweis, kein Sicherheitsmerkmal).
- [ ] Jede schreibende Aktion ueber Services -> Audit
      (bestehende Konventionen).
- [ ] Audit-Fehler ist fail closed
      (Service-Aufruf bricht ab).

## J. Logging

- [ ] NIEMALS loggen: Passwoerter, Tokens, Session-IDs,
      SECRET_KEY, password_hash, CSRF-Token.
- [ ] NIEMALS den vollen Request-Body bei Login.
- [ ] Fehlerantworten generisch
      ("Ungueltige Anmeldedaten").
- [ ] Details nur intern (Log), nicht im HTTP-Response.

## K. Konfiguration

- [ ] DEBUG=False in Produktion. Flask-Debug-PIN ist eine
      Hintertuer.
- [ ] SECRET_KEY aus .env.
- [ ] SESSION_COOKIE_SECURE=True (HTTPS/Tailscale).
- [ ] Kein Wildcard-Host (Host-Header-Validierung).
- [ ] MAX_CONTENT_LENGTH setzen (Body-Size-Limit).

## L. Deployment

- [x] Dashboard laeuft hinter Reverse-Proxy (nginx/caddy)
      oder nur ueber Tailscale.
- [x] NICHT direkt ins Internet.
- [x] systemd-Service mit User=, ProtectSystem=strict,
      NoNewPrivileges.
- [x] Binding auf 127.0.0.1 oder Tailscale-Interface,
      nicht 0.0.0.0 (falls ohne Proxy).

Erfuellt durch Phase 3.6.12 (nginx Reverse-Proxy mit TLS).
Siehe docs/DEPLOYMENT.md Abschnitt 3c.

## M. Test-Ebene

- [ ] Login: erfolgreich, falsches Passwort, inaktiver
      Principal, fehlender password_hash.
- [ ] RBAC: 403 ohne Permission fuer jede Route.
- [ ] CSRF: POST ohne Token -> 400/403.
- [ ] Session-Timeout nach Idle.
- [ ] XSS: HTML in Chat-Antwort wird escaped.
- [ ] Rate-Limit: zu viele Requests -> 429.
- [ ] Logout: Session serverseitig ungueltig.

## N. Was NICHT ins Dashboard gehoert

- Kein direktes DB-Schreiben (nur ueber Services).
- Keine Tool-Aufrufe (nur ueber AgentLoop).
- Keine Entscheidungen des LLM (nur Erklaerungen).
- Kein Konfig-Aenderung (nur Change Requests).
- Kein Secret-Handling (nur Anzeige von Status).
- Kein direkter Systemzugriff (kein Shell, kein subprocess).

## O. Reihenfolge der Umsetzung

1. Login-Route + Session + CSRF + Audit.
2. RBAC-Middleware (before_request).
3. Dashboard (read-only, keine Aktionen).
4. Inventar + Alarme (read-only).
5. Approvals + Changes (Aktionen ueber Services).
6. Chat (ruft ChatService).
7. Benutzer + Rollen (nur principal.manage).
8. Audit-Ansicht (nur audit.read).
9. Einstellungen (read-only oder Change Request).

## P. Bei Abweichung

Wenn ein Punkt nicht eingehalten werden kann:
- STOP, nicht durchwinken.
- Begruendung im Commit oder Code-Kommentar.
- Review durch den Audit-Chat (dieser Chat).
