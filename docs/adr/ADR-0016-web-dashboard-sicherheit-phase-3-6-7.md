# ADR-0016: Web-Dashboard-Sicherheit (Phase 3.6.7)

- **Status:** accepted
- **Datum:** unbekannt (migriert 2026-10-31)
- **Quelle:** docs/DECISIONS.md §16

---

## 16. Web-Dashboard-Sicherheit (Phase 3.6.7)

### CSP streng ohne unsafe-inline

Der CSP-Header ist streng:

    default-src 'self';
    script-src 'self';
    style-src 'self';
    img-src 'self' data:;
    font-src 'self';
    connect-src 'self';
    frame-ancestors 'none';
    base-uri 'self';
    form-action 'self';
    object-src 'none'

Kein 'unsafe-inline', kein 'unsafe-eval'.

Grund: Style-Injection ist ein realer XSS-Vektor
(CSS-Exfiltration, Clickjacking-Vorbereitung).
'unsafe-inline' in style-src schwaecht die ganze CSP.

Konsequenz:

- Kein `style="..."` in Templates.
- Kein `<style>`-Block.
- Kein `onclick=`, `onchange=`, `onsubmit=` usw.
- Kein inline `<script>`.
- Externe Stylesheets und Scripts nur lokal.

Dynamische Styles (Chart-Balken, Progress) nur via
`element.style.setProperty(...)` in JS. `<div
style="width:50%">` wird von `style-src 'self'`
blockiert. `el.style.width = "50%"` ist erlaubt
(CSSOM wird nicht von style-src blockiert).

### Weitere Security-Header

    X-Content-Type-Options: nosniff
    X-Frame-Options: DENY
    Referrer-Policy: same-origin
    Permissions-Policy: geolocation=(), camera=(),
                        microphone=(), payment=(),
                        usb=(), interest-cohort=()

### after_request

Alle Security-Header werden in `@app.after_request`
gesetzt. Greift auch auf 500er und Redirects.

### CSRF-Makro

`_helpers.html` enthaelt `csrf_field(token)` als Makro.
Token wird als Kontext-Variable uebergeben (nicht als
globale Jinja-Funktion). Kein context_processor.

### |safe-Verbot

`|safe` nur mit:

1. Dokumentation in dieser Datei.
2. Test in `tests/unit/test_templates_xss.py`.

Kein `|safe` fuer User-Input.

### _safe_next (Open-Redirect-Schutz)

`_safe_next(raw)` schuetzt vor Open-Redirect:

- Blockt `""` (leer) -> `/`
- Blockt Werte ohne fuehrendes `/`
- Blockt `//` (protokoll-relativ)
- Blockt `/\` (Backslash-Bypass in Chrome)
- Blockt `\r`, `\n`, `\x00` (Header-Injection)
- URL-Decode einmal (urllib.parse.unquote) VOR der
  Validierung: `%2F%2Fevil.com` und `/%%5Cevil.com`
  werden erkannt.

### html.escape in auth.py entfernt

`login_form` uebergibt `next` **roh** an das Template.
Jinja escaped automatisch (`autoescape=True`).
Doppeltes Escaping (`html.escape` + Jinja) wuerde
`&amp;lt;` statt `&lt;` erzeugen.

### stat_card.html als Makro

`{% include "x.html" with a=1 %}` ist **keine** gueltige
Jinja2-Syntax. Fuer Partial-Parameter wird ein Makro
verwendet:

    {% macro stat_card(label, value, accent="cyan") %}
    <div class="card card-accent-{{ accent }}">
      <div class="card-label">{{ label }}</div>
      <div class="card-value">{{ value }}</div>
    </div>
    {% endmacro %}

### Test-Fixtures in _helpers.py

Dashboard-spezifische Fixtures (`build_dashboard_app`,
`set_session_cookie`) liegen in
`tests/unit/_helpers.py`, NICHT in `tests/unit/conftest.py`.

Grund: `conftest.py` gilt fuer ALLE Unit-Tests. Andere
Tests koennten die dashboard-spezifische Fixture
versehentlich anfordern und einen unerwarteten Zustand
bekommen.

### venv und CWD

- Immer `/opt/security-ai/.venv/bin/python3`.
  Nicht `/usr/bin/python3`.
- Tests immer aus `/opt/security-ai` (CWD).
  Grund: `detection/rules.yaml`, `policies/tools.yaml`,
  `core/risk/rules.yaml` werden relativ zum CWD geladen.
- `scripts/*` sind Werkzeuge, keine Bibliothek.

### Test-Fixtures: Cookie-Flags

Der Test-Client setzt Session-Cookies mit den gleichen
Flags wie die Produktion:

    secure=True, httponly=True, samesite="Strict"

Sonst wird nicht das echte Verhalten getestet.

### HTML-Formular login

`login.html` ist standalone (kein `extends base.html`):

- Kein Sidebar, kein Topbar.
- Eigenes `<head>` mit CSS-Links.
- `variables.css` ZUERST, dann `reset.css`,
  `layout.css`, `components.css`, `main.css`.
- Kein `chat.css` (Login hat keinen Chat).
- CSRF-Feld via `csrf_field(token)`-Makro.
- `action="/login"` (doppelte Quotes).


### display: block auf .table (CSP-relevant, 3.6.10)

Eine Aenderung der Tabellen-Semantik (display: block auf
.table) wuerde die Spaltenberechnung aushebeln und ist
CSP-relevant. Sie wird nicht verwendet.

Responsive Loesung heute (3.6.10):
- table-layout: fixed + word-break fuer die Zellen.
- nowrap+ellipsis fuer die Zeitstempel-Spalte (14ch).
- nth-child(n+4) display: none bei <500px.

### Globale Suche (3.6.16)

- Neue Permission search.run (Migration 0008).
  admin + operator. viewer + system NICHT.
- GET /search?q=..., rein lesend, kein CSRF.
- Query-Validierung im Service (A538):
  Laenge 2-200, Zeichen-Whitelist [A-Za-z0-9 ._:/@-].
- LIKE '%q%' mit LOWER() und ESCAPE (A527/A528):
  %, _, \\ werden escaped. Keine Wildcard-Injektion.
- Nur identifizierende Felder durchsuchen (A530).
  Keine Freitextfelder (description, diff_or_patch,
  rollback_plan, test_plan, args_json, decision_reason,
  notes).
- Permission pro Quelle (A525/A526). Quellen ohne
  Permission werden aus dem Ergebnis entfernt, ohne
  Hinweis auf ihre Existenz.
- 20 Treffer pro Quelle, kein "Erste 20 von N"
  (A531/A371).
- Link-Builder als Jinja-if-Baum pro Quelle (A545),
  kein generischer Pfad.
- Schichtung: SearchService -> SearchRepository -> DB.
  Kein Service baut SQL. Keine bestehenden Repos
  angefasst (A553-A557).
- risk_assessments kommen aus JSONL (read_risk_assessments),
  Python-Filter im SearchService (A557).

### Links im Chat (Punkt 30, Auflagen 757-772)

fact/detail_append-Antworten liefern eine
strukturierte Link-Liste (core/context/links.py).
Regeln:
- Nur interne Pfade (Whitelist: /audit/, /changes/,
  /approvals/, /inventory/, /users/, /roles/).
  Kein externer Link, kein mailto, kein javascript:.
- RBAC pro Link (AccessChecker.check).
- Kein Href aus dem Text (Href wird aus der ID gebaut).
- Label = Rohstring, Client rendert via textContent.
- LLM-Antworten werden nicht verlinkt (A758).
Client-Rendering: renderLinks in chat.js,
createElement("a"), kein innerHTML.

### Navigations-Links im Fact-Pfad (Punkt 33, Auflagen 858-881)

Zusaetzlich zu `links` (Objekt-Referenzen) liefert
der Fact-Pfad ein eigenes Feld `nav_links` fuer
Navigations-Hinweise. Getrennt, weil `links` auf
IDs verweist und `nav_links` auf Routen.

- `ChatResponse.nav_links: list[dict]` (Default []).
- Nur bei `fact_kind == "auff_ja"` UND
  `alert.view` (RBAC im ask()-Zweig, kein Log).
- Inhalt: `{"label": "Alle Alarme ansehen",
  "href": "/alerts"}`.
- Kein Markup im answer-Text.
- Whitelist: `/alerts` exakt (`_ALLOWED_EXACT`).
  `/alerts/foo` bleibt verboten.
- Client: `renderNavLinks` in chat.js, nach
  `renderLinks`. createElement("a"), textContent,
  kein innerHTML.
- API-Antwort hat jetzt 8 Schluessel (answer, model,
  model_reason, source, denied, answer_id, links,
  nav_links).

### User-Menue-Dropdown: JS-Ausnahme (A711, A749)

Das User-Menue-Dropdown ist die einzige Ausnahme
von der Regel "kein JS in Templates". Es nutzt
<details>/<summary> + ein separates user_menu.js
fuer Klick-ausserhalb-Schliessen. Kein Inline-JS,
kein onclick=, keine Aenderung an nav.js.
Jede weitere JS-Anforderung braucht einen eigenen
Reviewer-Block.

### ProxyFix (Punkt 16a, bd7d187)

ProxyFix aktiv (x_for=1, x_proto=1, x_host=1),
weil nginx einziger vorgelagerter Proxy ist.
Login-Rate-Limit greift dadurch pro Client
statt global.

### server_name (3.6.12)

server_name akzeptiert zusaetzlich 127.0.0.1 und localhost.
Grund: lokale Diagnose ohne Host-Header-Trick.
Externe Zugriffe bleiben auf 192.168.178.117 und
security-ai.local beschraenkt. Kein Sicherheitsverlust,
weil beide Namen nur lokal aufloesen.

### default_server (3.6.12)

Ein expliziter default_server auf Port 80 und 443 liefert
return 444. Grund: unbekannter Host-Header soll kein
Info-Leak (Login-Seite) zeigen. Der 443-default_server
hat ein Zertifikat, weil TLS-Handshake vor HTTP-Routing
stattfindet.
