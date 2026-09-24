# WORKFLOW — Zusammenarbeit mit einem Bau-Chat

Dieser Text beschreibt, wie die Zusammenarbeit zwischen
einem Menschen und einem KI-Assistenten ("Bau-Chat")
ablaeuft. Er ist **projektunabhaengig** und kann in jedes
neue Projekt kopiert werden. Pro Projekt bleibt die Frage,
welche Datei- und Commit-Konventionen gelten — die
Prozess-Regeln hier sind ueberall dieselben.

## Rollen

- **Mensch** ist die Hand. Er fuehrt Befehle aus, pastet
  Ausgaben zurueck und entscheidet bei Eskalationen.
- **Bau-Chat** plant, baut, verifiziert, committet.
- **Reviewer** (optional, eigener Chat) prueft
  sicherheitsrelevante Aenderungen vor der Ausfuehrung.

## Fakten-Check-Takt (verbindlich)

- **Ein Ausfuehrungsblock pro Nachricht.** Der naechste
  Block kommt erst, nachdem der Mensch die Ausgabe des
  vorherigen gepastet hat.
- **Kein Vorab-Stapeln.** Nicht "hier noch zwei Bloecke
  zur Sicherheit" — das erzeugt Scroll-Chaos.
- **Mehrere Fakten sequenziell klaeren**, nicht parallel.
- **Bei Unklarheit: STOPP + Frage.** Eine ungestellte
  Frage kostet eine Runde; falsch gebauter Code kostet
  Rollback, Vertrauen und Stunden.

## Oberste Regel: Faktenlage, nicht raten

- **Verboten:** Signaturen aus dem Gedaechtnis, API-Namen
  aus dem Gedaechtnis, "das war schon immer so",
  "sollte passen" als Begruendung, Zahlen schaetzen
  statt messen, Datei-Inhalte annehmen statt `cat`.
- **Pflicht:** `cat`, `grep`, `sed -n`,
  `inspect.signature`, `pytest --collect-only` vor
  `pytest`, ehrliches "Ich weiss es nicht".
- **Vor jedem Patch einer bestehenden Datei: erst
  `cat`.** Anker-Strings muessen aus dem echten Inhalt
  stammen.
- **Patches per Python-Skript** mit
  `assert text.count(anker) == 1`. Kein `sed` auf
  Python-Code. `cat >` nur bei neuen Dateien.
- **API-Signaturen pruefen:** `inspect.signature` bei
  jedem Bibliotheks-Aufruf, dessen Signatur nicht aus
  einem vorherigen `cat`/`grep` stammt.

## Kategorien

- **Kategorie 1 (trivial):** Tippfehler, Kommentare,
  Docstrings, Formatierung, Doku. Der Bau-Chat macht
  und committet.
- **Kategorie 2 (wichtig):** Tests, Refactorings ohne
  Verhaltensaenderung, neue Helper ohne
  Sicherheitsbezug. Selbst-Review, dann committen.
- **Kategorie 3 (kritisch):** Auth, RBAC, CSP, Secrets,
  SQL, Input-Validierung, Output-Escaping, DB-Schema,
  Kern-Services, Audit. **Code VOR Ausfuehrung an
  Reviewer.** Warten auf GO / NO-GO / ESKALATION.

### Reviewer-Konventionen

- **Auflagen-Nummern sind global fortlaufend**, nicht
  pro Runde. Wenn eine Runde 1-10 vergibt und die
  naechste 11-20, referenziert der Bau-Chat die
  Nummern in Commit-Messages und Selbst-Review.
- **Bei NO-GO: Plan korrigieren, nicht improvisieren.**
  Nicht "mal schnell" einen Punkt aendern und
  weitermachen. Der korrigierte Plan geht an den
  Reviewer, dann GO, dann Bau.
- **Reviewer-Blocks immer in einen Codeblock**, damit
  der Mensch sie sauber kopieren kann. Freitext wird
  beim Einfuegen oft als Shell-Befehl interpretiert.
- **Eskalation statt Vermutung.** Wenn der Reviewer
  eine Frage stellt, die der Bau-Chat nicht aus
  Fakten beantworten kann: zurueckfragen, nicht
  raten.

## Selbst-Review (Pflicht vor jedem Commit)

Jeder Commit (auch Kategorie 1) bekommt ein
schriftliches Selbst-Review mit sechs Punkten:

1. **AENDERUNG:** welche Datei, welcher Zweck.
2. **TESTS:** Namen, erwartet vs. tatsaechlich.
3. **AUSGABE:** Zahlen (`wc -l`, `py_compile`,
   `pytest -q`).
4. **RISIKEN:** konkrete Gefahren, keine Floskeln.
   Wenn keine: "keine erkannt, weil <Grund>".
5. **AUFLAGEN:** Auflage-Nummer + wo im Code umgesetzt.
   Nicht "die meisten" — alle.
6. **KATEGORIE:** 1/2/3 mit Grund.

Verboten im Selbst-Review: "sieht gut aus" ohne
konkrete Punkte, "alle Tests gruen" ohne Zahlen,
"keine Aenderung am Verhalten" ohne Begruendung,
Punkt 4 weglassen.

## Doku-Pflege

- Jeder abgeschlossene Unterschritt bekommt einen
  Eintrag in der Phasen-Doku (Status, Commit-Hash,
  Kurzbeschreibung).
- Sicherheitsentscheidungen kommen in ein
  Review-Log (thematisch, nicht chronologisch).
- Offene Punkte bleiben sichtbar (eigener Abschnitt
  im Review-Log oder separate Datei).
- Inkonsistenzen werden nicht geloescht, sondern
  ausgelagert (Verweis statt Inhalt).
- Der Einstiegs-Prompt (`CONTEXT_PROMPT.md` in
  diesem Projekt) wird aktuell gehalten: Test-Zahl,
  naechster Schritt, Verweise.

## Patch-Template (verbindlich)

Fuer jede Aenderung an einer bestehenden Datei:

    from pathlib import Path

    p = Path("pfad/zur/datei")
    text = p.read_text(encoding="utf-8")
    anker = "..."   # exakt aus cat, nicht aus dem Gedaechtnis
    assert text.count(anker) == 1, f"count={text.count(anker)}"
    text = text.replace(anker, neu, 1)
    p.write_text(text, encoding="utf-8")
    print("patched <datei>")

Regeln:

- Kein `sed` auf Python-Code.
- Kein `cat >` bei bestehenden Config- oder Doku-Dateien.
  Nur bei neuen Dateien. Sonst gehen Inhalte verloren
  (Beispiel: `.env.example`, `PROJECT_VISION.md` Stufe 2.5).
- Der `assert` ist Pflicht, nicht optional. Wenn der
  Anker mehrfach oder gar nicht vorkommt: STOPP, cat
  nochmal, Anker korrigieren.
- Nach dem Patch: `wc -l`, `py_compile` (bei Python),
  `pytest -q` (bei Logik-Aenderung).

## Verifikations-Reihenfolge (verbindlich)

Nach jedem Patch, in dieser Reihenfolge:

1. `wc -l` auf die geaenderte Datei (Zahlen notieren).
2. `py_compile` (wenn Python) — Syntaxfehler sofort finden.
3. `pytest --collect-only -q <datei>` — Sammelfehler finden.
4. `pytest -q <datei>` — Lauf.
5. `pytest -q` (Vollsuite) vor dem Commit, wenn Logik
   betroffen ist. Bei reiner Doku entfaellt das.
6. `git status --porcelain` — keine versehentlichen
   Dateien, keine unerwarteten Aenderungen.
7. `git diff --stat` — Umfang pruefen, bevor committet wird.

Erst dann `git add` + `git commit`. Nach `git push`:
`git log --oneline -1` als Beleg.

## Umgang mit unklaren Zustaenden

### Abgebrochener Paste

Wenn ein Paste zerhackt aussieht (Shell-Marker wie
`$'\E[200~'`, Heredoc-Ende fehlt, Zeilen halb abgeschnitten):

- **Nicht weiterlaufen.** Erst pruefen, ob der Befehl
  ueberhaupt ausgefuehrt wurde.
- Pruefen: `ls -la <erwartete-datei>`,
  `wc -l <datei>`, `git status --porcelain`.
- Erst dann: entweder Schritt wiederholen oder
  Ergebnis akzeptieren, je nach Zustand.
- Symptom im Chat melden, nicht interpretieren.

### Widerspruch zwischen Ausgabe und Realitaet

Wenn `py_compile` meldet `ok`, aber `wc -l` sagt
"Datei nicht gefunden":

- Das ist ein Zeichen fuer einen kaputten Paste.
- Nicht weiterlaufen. Erst `ls -la` und `head` auf
  die Datei, bis der echte Zustand bekannt ist.
- Kein "wird schon passen".

### Phantom-Dateien

Wenn `git status --porcelain` unerwartete Dateien
listet (z. B. `200.`, `True,`, `DB-Hash`):

- Das sind Reste aus versehentlich in die Shell
  gepasteten Text.
- Pruefen mit `ls -la -- '<name>'`, dann gezielt
  loeschen (`printf '%s\0' '<name>' | xargs -0 rm --`).
- **Nie** `rm -rf` mit Wildcard auf Projektverzeichnis.
- Nach dem Loeschen: `git status --porcelain` muss
  nur die erwarteten Aenderungen zeigen.

## Anti-Patterns aus der Praxis

Konkrete Fehler, die in Sessions aufgetreten sind.
Generisch formuliert, damit sie uebertragbar sind.

### API aus dem Gedaechtnis

Aufruf von `RoleRepository.create(...)` — die Methode
existiert nicht. `AttributeError`.

- **Regel:** Jede Bibliotheks- oder Projekt-API mit
  `grep`/`cat`/`inspect.signature` verifizieren, bevor
  sie aufgerufen wird.

### Modul-Konstante vs. Instanz-Wert

`monkeypatch.setattr(module, "MAX_REQUESTS", 2)`
bringt nichts, wenn eine Modul-globale Instanz beim
Import mit dem alten Wert gebaut wurde. Der Test
misst den falschen Wert.

- **Regel:** Bei Tests, die Modul-Konstanten
  beinflussen wollen, die tatsaechlich verwendete
  Instanz patchen, nicht die Konstante. Oder die
  Instanz ueber eine Factory pro Test bauen.

### Service liest Default-Pfad statt Konfig

`read_risk_assessments(base_dir=...)` ohne `base_dir`
liest relativ zum CWD, nicht zur App-Konfig. Bug:
Dashboard zeigt echte CWD-Logs, Test schreibt in
tmp-Verzeichnis — nie sichtbar, weil die Tests mit
leerem CWD gruen waren.

- **Regel:** Bei Services, die Pfade lesen: pruefen,
  dass der Pfad aus der Konfiguration kommt, nicht
  aus dem Default. Regressionstest mit zwei Pfaden
(tmp + CWD) bauen.

### Test-Name kollidiert mit Substring-Check

`test_settings_no_secret_key_in_body` -> pytest baut
`tmp_path` mit dem Testnamen
(`test_settings_no_secret_key_in0/audit`). Der Pfad
wird im Response angezeigt -> Substring-Check auf
`b"secret_key"` schlaegt fehl, obwohl kein Leak da ist.

- **Regel:** Testnamen neutral waehlen, wenn der Name
  in Pfade einfliessen kann (pytest tmp_path). Oder
  Marker-Checks auf spezifische Strings einschraenken.

### Unmatched Route ist 403, nicht 404

`GET /approvals/` matcht die Route
`/approvals/<request_id>` nicht (Default-Converter
matcht kein `/` und nicht leer). `before_request`
findet keine View mit `_required_permission` ->
403 statt 404.

- **Regel:** Wenn ein Test 404 erwartet, aber 403
  kommt, erst pruefen ob die Route ueberhaupt matcht.
  Fail closed (403) ist korrekt fuer unmatched Routes,
  der Test gehoert in eine eigene Kategorie.

### Fail open bei Betriebsfehler als 4xx

DB-Ausfall als 400 "Ungueltige Anfrage" maskiert:
der Nutzer denkt, er habe sich vertippt, obwohl das
System gestoert ist.

- **Regel:** Format-Fehler -> 4xx (ServiceError).
  Betriebsfehler -> 5xx (OperationError). Nicht
  vermischen. Kein `except Exception: return 400`.

### Heredoc-Ende zerhackt

`cat > datei <<'EOF'` -> das `EOF` kommt im Paste
nicht mit an, die Shell interpretiert den Rest des
Textes als Befehle.

- **Regel:** Nach `cat >`-Bloecken immer verifizieren
  (`ls -la`, `wc -l`, `tail -3`, `py_compile`).
  Wenn Datei fehlt oder zu kurz: Schritt wiederholen,
  nicht weitermachen.

### Fehlender `assert` im Patch

`text.replace(anker, neu)` ohne `assert
text.count(anker) == 1` schreibt auch dann, wenn der
Anker mehrfach oder gar nicht vorkommt. Inhalte gehen
verloren.

- **Regel:** `assert` ist Pflicht. Bei
  `count != 1`: STOPP, `cat`, Anker korrigieren.
## Sprache und Format

- Keine Umlaute in Code-Bloecken (oe/ue/ae/ss).
- Im Fliesstext der Doku ebenfalls keine Umlaute,
  damit Copy-Paste in Terminal und Codebloecke
  nicht bricht.
- Ein `&&`-Block pro logischer Einheit. Bei
  Fehlschlag bricht die Kette vor `git commit` ab;
  der naechste Block zieht nur die unfertige Datei
  nach.
- Kein `request.get_json()` ohne `silent=True`
  und `None`-Check.
- Kein `|safe` ohne Doku + Test.
- Kein `style="..."`, kein `on*=`, kein inline
  `<script>` in Templates, wenn CSP `'self'` gilt.

## Fail closed

- Bei Fehlern lieber ablehnen als durchlassen.
- Fehlende Pflichtabhaengigkeiten (Audit-Writer,
  Checker, Repos) -> Fehler, nicht stiller
  Fallback.
- Format-Fehler -> 4xx. Betriebsfehler -> 5xx.
  Nicht vermischen.
- Unbekannte Objekte -> 404. Fehlende Berechtigung
  -> 403. Fehlende Auth -> Redirect auf Login.

## Commit-Konventionen

- Ein Commit pro logischer Einheit.
- Keine kuenstliche Zweiteilung ("Feature" +
  "Test-Fixup") wenn beides zusammen hingehoert.
- Commit-Message nennt: Unterschritt, was drin ist,
  Review-Ergebnis (z. B. "Reviewed: GO mit Auflagen
  N-M").
- Bei laengeren Messages: `git commit -F -` mit
  Heredoc, damit nichts abreisst.

## Handoff an einen neuen Chat

Wenn die Session gewechselt wird (Kontext zu gross,
Thema wechselt):

1. Alle offenen Punkte sind in der Doku.
2. Der Einstiegs-Prompt ist aktuell.
3. Der Mensch gibt dem neuen Chat einen kurzen
   Spickzettel: Projekt, HEAD, Test-Zahl, naechster
   Schritt, Verweis auf den Einstiegs-Prompt.
4. Der neue Chat liest zuerst den Einstiegs-Prompt,
   dann die Phasen-Doku und das Review-Log.
5. Der neue Chat bestaetigt in 2-3 Saetzen, dass er
   den Kontext verstanden hat, und fragt, ob es
   losgeht.

## Was nicht verhandelbar ist

- Faktenlage vor Meinung.
- Fail closed vor "weiterlaufen".
- Nachvollziehbarkeit (Audit, Doku, Commit-Message)
  vor Bequemlichkeit.
- Ein Block pro Nachricht.
- Fragen stellen statt raten.

## Kontext-Hygiene

- Antworten kurz halten. Kein Vorlauf, keine
  Zusammenfassungen ohne Anlass.
- Stichpunkte statt Prosa bei Status-Updates.
- Ein Ausfuehrungsblock pro Nachricht, direkt,
  ohne Einleitung.
- Bei absehbarer Session-Laenge: Plaene und
  Auflagen zuerst ins Repo sichern (PHASES.md,
  CONTEXT_PROMPT.md), dann weiterbauen.
- Bei abgeschnittenem oder zerhacktem Paste:
  zuerst Bestandsaufnahme (ls, wc -l, git status),
  erst dann naechster Schritt.
