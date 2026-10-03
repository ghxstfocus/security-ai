# WORKFLOW — Zusammenarbeit mit einem Bau-Chat

Dieser Text beschreibt, wie die Zusammenarbeit zwischen
einem Menschen und einem KI-Assistenten ("Bau-Chat")
ablaeuft. Er ist **projektunabhaengig** und kann in jedes
neue Projekt kopiert werden. Pro Projekt bleibt die Frage,
welche Datei- und Commit-Konventionen gelten — die
Prozess-Regeln hier sind ueberall dieselben.

## Verbindlichkeits-Hierarchie

Drei Stufen:

1. **VERBINDLICH (Hard-Rules).** Nicht abdingbar.
   Verstoss = STOP, keine Ausfuehrung. Der Bau-Chat
   prueft diese Regeln VOR jedem Ausfuehrungsblock.
2. **Pflicht (Routine).** Nach jedem Schritt. Verstoss =
   Korrektur im naechsten Block. Selbst-Review,
   Doku-Pflege, Commit-Konventionen.
3. **Empfehlung (Praxis).** Nuetzlich, aber
   situationsabhaengig. Anti-Patterns, Kontext-Hygiene.

Die Hard-Rules sind kurz und konkret. Wenn eine Regel
im Zweifel ausgelegt werden muss, gilt die restriktivere
Auslegung.

### Hard-Rules (VERBINDLICH)

HR1. Faktenlage vor Meinung. Keine API aus dem
     Gedaechtnis. Keine Datei-Inhalte annehmen. Keine
     Zahlen schaetzen. Gemessen wird konkret:
     Testzahl mit `pytest --collect-only -q | tail -1`,
     Zeilenzahl mit `wc -l`, API-Signatur mit
     `inspect.signature`, Datei-Inhalt mit `cat` oder
     `sed -n`. Immer messen, nicht erinnern.
     Beispiel: 728-Testzahl aus Handoff uebernommen,
     korrekt war 720.

HR2. Ein Ausfuehrungsblock pro logischer Einheit,
     nicht pro Nachricht. Mehrere `&&`-verkettete
     Einheiten in einem Block sind ok, solange sie
     zusammen ein Ergebnis liefern (z. B. Backup +
     init_db + Verify). Nicht ok: fuenf unabhaengige
     Ausfuehrungen, deren Ergebnis der Mensch
     einzeln pasten muesste.

HR3. Vor `cat >` auf eine angeblich neue Datei:
     `git ls-files <pfad>` UND `git status --porcelain`
     pruefen. Kein Treffer in beiden = neu.
     Treffer in einem = bestehende Datei,
     Patch-Skript mit `assert`, kein `cat >`.

HR4. Nach jedem Patch einer bestehenden Datei:
     `assert text.count(anker) == 1`.
     Bei count != 1: STOP, `cat`, Anker korrigieren.
     Bei count == 2 mit inhaltlich gleichen Ankern:
     Blockanker bauen (umgebenden `def`-Rahmen
     mitnehmen).

HR5. Nach jedem Patch, der Tests betrifft:
     `pytest --collect-only -q <datei>` VOR
     `pytest -q <datei>`. Die Sammelzahl muss der
     Erwartung entsprechen. Sonst: STOP, Ursache
     sehen, bevor Tests interpretiert werden.

HR6. `git status --porcelain` zeigt `M` bei einer
     Datei, die als "neu" angekuendigt war: STOP.
     `git ls-files` und `git log -- <pfad>` klaeren,
     bevor committet wird.

HR7. Kategorie 3 (typische Themen, nicht
     abschliessend: Auth, RBAC, CSP, Secrets, SQL,
     Input-Validierung, Output-Escaping, DB-Schema,
     Audit, Kern-Services). Kern-Services konkret:
     core/services/*, apps/security_ai/chat.py,
     harness/approval/*, harness/audit/*,
     harness/policy_engine/*. Code VOR Ausfuehrung
     an den Reviewer. Kein Improvisieren nach NO-GO.
     Bei Zweifeln an der Kategorie: Reviewer.

HR8. Doku-Pflege ist Pflicht (siehe §Doku-Pflege).
     Ein Unterschritt gilt erst als abgeschlossen,
     wenn die zugehoerige Doku nachgezogen ist.
     Ein Commit ohne Doku-Nachzug ist ein
     unvollstaendiger Commit.

HR9. Reviewer-Blocks immer in einen Codeblock.
     Freitext, direkt in die Shell gepastet, erzeugt
     Phantom-Dateien. Beim Weiterleiten: Backtick-
     Rahmen mitkopieren. Bei Blocks > ~3 KB:
     Patch-Skript in `/tmp` schreiben, dort
     verifizieren, dann ausfuehren. Kein Heredoc in
     die interaktive Shell.
     KONKRET: `python3 /tmp/patch.py` (Skript als
     Datei), NICHT `python3 - <<'PY'` (Heredoc in
     die Shell). Nur so ist der Patch reproduzierbar,
     nachpruefbar und im Fehlerfall wiederholbar.
     Verstoss = Prozessfehler, im Selbst-Review
     unter RISIKEN nennen.
     Anker-Messung Pflicht: bei jedem Patch, der
     mehrzeilige Anker nutzt, den Anker IM Patch-
     Skript ermitteln (lines.index, text.find,
     Zeilennummer aus text.split), nicht im Chat
     aus grep/wc ableiten. Bei mehrzeiligen Ankern
     zeilenbasierter Schnitt statt String-Anker.

HR10. Reviewer-Update nach jedem Block/Phase.
      Nach jedem abgeschlossenen Block (Phase,
      Zwischenblock, Kategorie-3-Runde) bekommt
      der Reviewer ein Update: HEAD-Hash, Testzahl
      (gemessen), was erledigt wurde, welche
      Auflagen umgesetzt wurden, offene Punkte.
      Form: kopierbarer Block (siehe HR9).
      Grund: Der Reviewer bleibt im Bild, statt
      bei jedem neuen Block den Kontext neu
      aufzubauen. Kein Block gilt als
      abgeschlossen, bevor das Update raus ist.

## Reviewer-Update nach jedem Block (verbindlich)

Der Reviewer ist ein eigener Chat. Er hat keinen
Zugriff auf den Bau-Chat-Verlauf. Deshalb bekommt er
nach jedem abgeschlossenen Block ein Update. Ohne
dieses Update gilt der Block nicht als abgeschlossen.

Wann:

- Nach jeder abgeschlossenen Phase (PHASES.md-Block).
- Nach jedem Zwischenblock.
- Nach jeder Kategorie-3-Runde (auch wenn sie
  teilweise abgeschlossen ist).
- Nach einem groesseren Doku-Nachzug, wenn er
  mehrere Bereiche betrifft.

Was drinsteht (kurz, aber konkret):

- HEAD-Commit-Hash + Branch (origin/main synchron?).
- Testzahl (gemessen, nicht erinnert).
- Was in diesem Block passiert ist (Commits).
- Welche Auflagen umgesetzt wurden.
- Welche offenen Punkte noch stehen.
- Ob ein neuer Handlungsbedarf entstanden ist
  (z. B. neuer offener Punkt).

Form:

- Kopierbarer Codeblock (HR9).
- Kein Volltext der Doku. Verweise reichen.
- Keine Spekulation. Gemessene Fakten.

Nicht Pflicht:

- Bei reinen Test-Ergaenzungen ohne neuen Stand
  (z. B. Nachziehen eines vergessenen Tests im
  selben Block): kein eigenes Update.
- Bei Tippfehler-Korrekturen (Kategorie 1): kein
  eigenes Update.

Pflicht bleibt Pflicht: Ein Update ohne HEAD und
Testzahl ist kein Update.

Beispiel-Format (verbindlich):

    REVIEWER-UPDATE — <Block> abgeschlossen

    HEAD: <hash> (origin/main synchron?)
    Tests: <gemessen> passed (Vollsuite, venv)

    ABGESCHLOSSEN:
    - <Block> (<commit>, <commit>)
      Auflagen <N>-<M>.
      - <was gebaut wurde>

    OFFENE PUNKTE:
    - <Punkt>: <Status>

    NAECHSTER SCHRITT:
    - <was als naechstes>

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
- **Ausfuehrungsblocks > ~3 KB nicht in die interaktive
  Shell pasten.** Der Kernel puffert TTY-Eingaben in
  `N_TTY_BUF_SIZE` (4096 Byte); was darueber hinausgeht,
  wird abgeschnitten oder zerhackt. Patch-Skripte in
  `/tmp` schreiben, dort `py_compile` verifizieren,
  dann ausfuehren.

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
- **Zahlen aus Handoff, Selbst-Review oder einem
  vorherigen Chat sind Schaetzungen, bis sie gemessen
  sind.** Quelle der Wahrheit fuer die Testzahl ist
  `pytest --collect-only -q`.

## Kategorien

- **Kategorie 1 (trivial):** Tippfehler, Kommentare,
  Docstrings, Formatierung, Doku. Der Bau-Chat macht
  und committet.
- **Kategorie 2 (wichtig):** Tests, Refactorings ohne
  Verhaltensaenderung, neue Helper ohne
  Sicherheitsbezug. Selbst-Review, dann committen.
  Test-Anpassungen an gewolltes neues
  Produktverhalten (Tests werden rot, weil sich das
  Produkt geaendert hat, nicht die Tests) sind
  Kategorie 2 **mit** Reviewer-Block, wenn das
  Produktverhalten selbst Kategorie 3 war. Der Test
  ist die Quelle der Wahrheit fuer das Verhalten,
  nicht fuer den Wortlaut.
  Beispiel: 3.6.14 Badge-Text wechselt von
  Rohkategorie auf Anzeige-Label (Kategorie 3 wegen
  Score-Anzeige und Kategorie-Bezug). Test-
  Anpassungen in `test_dashboard_alerts.py` gingen
  ueber den Reviewer.
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

7. **DOKU:** welche Doku-Dateien wurden nachgezogen
   (Phasen-Doku, Einstiegs-Prompt, Review-Log,
   Design-Entscheidungen, WORKFLOW)? Wenn keine:
   warum nicht?

Verboten im Selbst-Review: "sieht gut aus" ohne
konkrete Punkte, "alle Tests gruen" ohne Zahlen,
"keine Aenderung am Verhalten" ohne Begruendung,
Punkt 4 weglassen, Punkt 7 weglassen.
Ein Selbst-Review ohne Punkt 7 ist unvollstaendig.

## Test-Konventionen (verbindlich)

- Klassen mit `*Tests`-Suffix **erben von
  `unittest.TestCase`**. Ohne Vererbung sammelt pytest
  sie nicht (Default `python_classes = Test*`).
- Alternativ: modulweite `def test_`-Funktionen
  (pytest-Standard).
- **Kein Wechsel der Konvention ohne Doku-Block.**
  Sonst kommen spaeter pytest-idiomatische Klassen
  ohne `TestCase` dazu und die Sammlung bricht.
- Nach jeder neuen Testdatei:
  `pytest --collect-only -q <datei>` muss die
  erwartete Zahl liefern, sonst STOP.
- Beispiel: 3.6.14 `test_filters.py` -- Klassen mit
  `*Tests`-Suffix ohne `unittest.TestCase`-Vererbung.
  `py_compile=OK`, `collect-only=0`. Fix: von
  `unittest.TestCase` erben lassen.

## Doku-Pflege (verbindlich)

Nach jedem abgeschlossenen Unterschritt ist der
Doku-Nachzug Pflicht. Ein Unterschritt gilt erst als
abgeschlossen, wenn die zugehoerige Doku nachgezogen
ist. Ein Commit ohne Doku-Nachzug ist ein
unvollstaendiger Commit.

Was zum Doku-Nachzug gehoert, generisch:

- **Phasen-Doku** — Status `✅` fuer den
  Unterschritt, Commit-Hash, Kurzbeschreibung. Neue
  Unterschritte bekommen einen eigenen Block.
- **Einstiegs-Prompt** — HEAD-Commit, Testzahl
  (gemessen, nicht erinnert), naechster Schritt,
  offene Reihenfolge.
- **Review-Log** — Chronologie-Zeile, offene Punkte
  aktualisieren (neue anhaengen, erledigte mit
  Erledigt-Vermerk behalten, nicht loeschen).
  Sicherheitsentscheidungen thematisch, nicht
  chronologisch.
- **Design-Entscheidungen** — nur wenn eine
  Design-Entscheidung getroffen wurde.
- **WORKFLOW.md** — nur wenn der Prozess selbst
  betroffen ist.

Die konkreten Dateinamen legt das Projekt in seinem
Einstiegs-Prompt fest. In diesem Projekt: siehe
`CONTEXT_PROMPT.md` §Projekt-Konventionen.

Weitere Regeln:

- Sicherheitsentscheidungen kommen in das Review-Log,
  nicht in die Chronologie-Liste.
- Offene Punkte bleiben sichtbar.
- Inkonsistenzen werden nicht geloescht, sondern
  ausgelagert (Verweis statt Inhalt).
- Der Doku-Nachzug ist eigener Commit ODER Teil des
  Abschluss-Commits — nie "spaeter" ohne konkreten
  Termin.

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
   `ruff check .` vor jedem Commit, der .py-Dateien
   aendert. Bei reinen Doku-Commits (.md, pyproject
   ohne Regel-Aenderung) entfaellt es.
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

### Auto-Fix-Regeln pruefen, nicht blind anwenden

`ruff --fix --select <CODE>` ist mechanisch, aber
nicht immer semantisch korrekt. Beispiel B010
(set-attr-with-constant): `setattr(x, "y", v)` wird
zu `x.y = v`. Bei `TypeVar(bound=Callable)` ist die
direkte Zuweisung nicht moeglich, mypy meldet
`attr-defined`. Der Fix war ruff-konform, aber eine
Regression (Punkt 41, 3b20891, korrigiert in 01466e0).

Regel: Vor einem Auto-Fix pruefen, ob die Regel im
konkreten Kontext passt. Wenn ein Fix mypy bricht:
STOP, Ursache sehen, `# noqa: CODE` mit Begruendung.

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

### Import-Nachtrag ohne ruff-Nachmessung

Beim Typisieren wurden Import-Zeilen ergaenzt
(from typing import Any, Response, LLMResponse).
Nach dem einzelnen Commit wurde nur mypy isoliert
gemessen, nicht ruff. Zwei I001-Regressionen
blieben unentdeckt, bis sie in der Abschluss-Messung
auftraten (A900-2b-2c, Auflage 1538, behoben in
12d9a28 und 81a3607).

- **Regel:** Nach jedem Commit mit Import- oder
  Signatur-Aenderung im Verifikationsblock
  `ruff check .` mitlaufen lassen.
  Sonst bleiben Import-Reihenfolge-Fehler
  unentdeckt und werden zur spaeteren Regression.

### Code-Commit ohne ruff-Messung

Symptom: Code wird committet, `ruff check .` laeuft
nicht im selben Block. I001- oder andere
Lint-Regressionen fallen erst beim naechsten Commit
auf, wenn die Kette (mypy, Tests, Diff) den Fehler
zufaellig sichtbar macht.

Beispiele:
- A900-2b-2c: zwei I001-Regressionen durch
  Import-Nachtraege, erst in der Abschluss-Messung
  entdeckt (behoben in 12d9a28 und 81a3607).
- S310: noqa waere RUF100 gewesen, weil S310 nicht
  im Default-Satz aktiv ist.
- S608/S603: noqa waere RUF100, siehe SECURITY_REVIEW_LOG
  Punkt 62.

- **Regel:** Vor jedem Commit, der .py-Dateien
  aendert, `ruff check .` ausfuehren. Bei reinen
  Doku-Commits (.md, pyproject ohne Regel-Aenderung)
  entfaellt es. Der Commit ist erst fertig, wenn
  `ruff` clean ist.

### ruff-Ausgabe vollstaendig lesen

Symptom: `ruff check .` wird ausgefuehrt, aber die
Ausgabe ist im Terminal oder Paste abgeschnitten.
Es wird "ruff clean" angenommen, obwohl die
tatsaechliche Meldung mehrere Fehler auflistet.
Die Fehler fallen erst beim naechsten Commit auf
und muessen in einem separaten Nachbesserungs-Commit
korrigiert werden.

Ein abgeschnittener Paste oder ein "Found N errors"
ohne die zugehoerigen Zeilen ist **keine Messung**.
Die Ausgabe muss vollstaendig gelesen werden, bevor
der Commit laeuft.

- **Regel:** Vor dem Commit die ruff-Ausgabe
  vollstaendig lesen. Wenn die Ausgabe aus
  Platzgruenden abgeschnitten ist, mit
  `ruff check . --output-format concise`
  erneut ausfuehren. Diese Form liefert eine
  Zeile pro Fehler und bleibt auch bei vielen
  Treffern lesbar. Alternativ:
  `ruff check . --statistics` fuer eine
  Zusammenfassung nach Regel-Code.

- **Regel:** `ruff check .` nicht als letzter
  Schritt einer `&&`-Kette unmittelbar vor
  `git commit` verketten. Besser: ruff als
  eigener Verifikations-Block, Ausgabe lesen,
  dann der Commit in einem separaten Block.

### Heredoc ueber ~3 KB zerhackt

`cat > datei <<'EOF'` mit mehr als ~3 KB Inhalt
bricht beim Paste in die interaktive Shell ab. Ursache
ist der Kernel-TTY-Puffer `N_TTY_BUF_SIZE` (4096 Byte);
was darueber hinausgeht, wird abgeschnitten oder
zerhackt. Das ist kein Shell-Bug, sondern ein
hardcoded Kernel-Limit.

- **Regel:** Patch-Skripte > ~3 KB in `/tmp` schreiben,
  dort mit `py_compile` verifizieren, dann ausfuehren.
  Kein Heredoc in die interaktive Shell.
- **Regel:** Nach jedem `cat >`-Block immer verifizieren
  (`ls -la`, `wc -l`, `tail -3`, `py_compile`).
  Wenn Datei fehlt oder zu kurz: Schritt wiederholen,
  nicht weitermachen.

Praxisbelege:
- 2026-09-29: Commit 3, PHASES-Duplikat (4 Anlaeufe).
- 2026-10-02/03 (Punkt 80): dreimal Heredoc in die
  interaktive Shell, dreimal zerhackt. Trotz
  bestehender HR9-Regel. Naechster Versuch jeweils
  mit `python3 /tmp/script.py` (Datei) erfolgreich.
  Lehre: HR9 ist nicht optional, sondern Pflicht.

### Anker aus dem Chat abgeleitet statt im Skript gemessen

Symptom: Patch-Skript laeuft mit assert count == 1,
aber AssertionError: count=0. Der Anker sieht im
Chat korrekt aus, ist im Skript aber zeichenweise
anders (mehrzeilige Heredocs, Sonderzeichen wie Paragraf,
TTY-Puffer-Effekte).

Beispiele 2026-09-29:
- Commit 3: Heredoc fragmentierte Skript-Text, sah wie
  ein Assertion-Fehler aus. Nach Status-Block:
  Patch war bereits erfolgreich durchgelaufen.
- PHASES-Duplikat: vier Anlaeufe.
  1. Heredoc: Anker still verstuemmelt, count=0.
  2. Index-Patch v1: Endindex 1160 aus wc -l
     abgeleitet, tatsaechlich Index 1162.
  3. Diagnose: split(chr(10)) 1164 Elemente,
     letzte Inhaltszeile Index 1162.
  4. Erfolg: Skript misst Anker selbst.

Regeln:
- Anker im Patch-Skript selbst ermitteln
  (lines.index, text.find, Zeilennummer aus
  text.split im selben Skript).
- Bei mehrzeiligen Ankern zeilenbasierter Schnitt
  statt String-Anker.
- Heredoc in die interaktive Shell nur bis ~1 KB,
  auch wenn der Inhalt selbst klein aussieht.
- Nach jedem Patch: git diff --stat und
  git status --porcelain pruefen.

### `cat >` auf eine bestehende Datei

`cat > datei <<'EOF'` auf eine Datei, die schon im Git
ist, ueberschreibt sie vollstaendig. Symptom: Datei
ploetzlich kuerzer, `git status --porcelain` zeigt `M`
statt `??`, oft mit Datenverlust (Session 2026-09-25:
`tests/unit/test_migrations.py`, 119 Zeilen verloren,
per `git checkout` zurueckgeholt).

- **Regel:** Vor `cat >` zwei Checks: `git ls-files
  <pfad>` (Treffer = bestehende Datei) und
  `git status --porcelain` (zeigt sie `M` statt `??`).
  Treffer in einem der beiden: Patch-Skript statt
  `cat >`.

### Tests geschrieben, aber nicht gesammelt

Symptom: `py_compile=OK`, `grep -c "^def test_"`
zaehlt N, aber `pytest --collect-only -q` liefert 0
oder weniger. Ursache meist Klassen mit `*Tests`-Suffix
ohne `unittest.TestCase`-Vererbung -- pytest-Default
ist `python_classes = Test*`.

- Beispiel: 3.6.14 `test_filters.py` -- Klassen
  `FormatTsTests`, `FormatScoreLabelTests`,
  `FormatScoreTests` ohne `unittest.TestCase`.
  `py_compile=OK`, `collect-only=0`. Fix: von
  `unittest.TestCase` erben lassen.
- **Regel:** Nach jeder neuen Testdatei
  `pytest --collect-only -q <datei>` pruefen. Zahl
  muss der Erwartung entsprechen.

### Fehlender `assert` im Patch

`text.replace(anker, neu)` ohne `assert
text.count(anker) == 1` schreibt auch dann, wenn der
Anker mehrfach oder gar nicht vorkommt. Inhalte gehen
verloren.

- **Regel:** `assert` ist Pflicht. Bei
  `count != 1`: STOPP, `cat`, Anker korrigieren.

### Reviewer-Freitext in die Shell gepastet

Auflagen-Wortlaut oder Begleittext aus dem
Reviewer-Chat wird direkt in die Shell gepastet,
nicht nur der Codeblock. Metazeichen (Backticks,
Hochkommas, `$`, Klammern) werden als Shell-Syntax
interpretiert.

Symptome:
- `command not found`-Ketten.
- Phantom-Dateien wie `main`, `200.`,
  `"Extern (nicht autorisiert)?"`.
- `HTTP 400 URL must be absolute`-Ausgaben, wenn
  eine URL als Kommando interpretiert wird.

- **Regel:** Nur den Codeblock kopieren, nicht den
  Begleittext. Nach jedem Paste `git status
  --porcelain` pruefen. Phantom-Dateien sofort
  entfernen.

### Rueckgabe-Typ beim Helper-Aufruf pruefen

Ein Helper wird mit einer Funktion aufgerufen,
die etwas anderes liefert als erwartet.
Python ist dynamisch, kein Compiler-Fehler.

Beispiel (T3, 2026-09-30): ein Helper
`_safe_count(fn)` erwartet, dass `fn()` eine
Sequenz liefert (`len()` wird intern aufgerufen).
Eine Aggregat-Methode (`count_by_network()`)
liefert direkt einen `int`. Zur Laufzeit:
`len(int)` -> `TypeError`. Der Fehler wird vom
Exception-Handler geschluckt und als
Fallback-Wert angezeigt (Kachel "—").

- **Regel:** Vor jedem Helper-Aufruf pruefen:
  Was liefert der Aufruf, was erwartet der Helper.
  Wenn der Helper `len()` nutzt, darf die Funktion
  keine Zahl liefern.
- **Regel:** Nach jedem neuen Helper-Aufruf die
  erwartete Ausgabe testen, nicht nur die
  Fehlerbehandlung.

### Heredoc-Escape bei mehrzeiligen Patches

Bei Heredoc-Patches mit `\n` im Text oder
Skripten > ~100 Zeilen zerhackt der TTY-Puffer
die Eingabe. Symptome:
- Patch-Skript laeuft nur teilweise.
- Literales `\n` landet in der Zieldatei
  (`SyntaxError: unexpected character after
  line continuation character`).
- `p.write_text` wird nicht erreicht, obwohl
  vorherige `print`-Ausgaben erscheinen.

- **Regel:** Patch-Skripte > ~100 Zeilen
  schrittweise mit `>>` an eine `/tmp`-Datei
  anhaengen. Nach jedem Teil: `wc -l`.
  Bei `\n` im Text: `chr(10)` statt `"\n"`,
  oder mehrzeilige Strings mit echten
  Zeilenumbruechen.

### Backtick-! in Commit-Messages

Ein Commit-Text, der ein Backtick-Ausrufezeichen enthaelt und per
`git commit -m` uebergeben wird, kann von der Shell als
History-Expansion interpretiert werden. Folge: Commit-Message wird
abgeschnitten, Datei trotzdem committet.

- **Regel:** Solche Zeichen vermeiden, oder
  `git commit -F /tmp/msg.txt` mit Datei nutzen.

Vorfall: Punkt 83 (2026-10-02), Commit 3784998.

### Hash-Zirkel in Doku-Eintraegen

Wenn ein SECURITY_REVIEW_LOG-Eintrag den Commit-Hash enthaelt,
der ihn selbst committet, entsteht ein Amend-Zirkel: der Hash
aendert sich bei jedem Amend.

- **Regel:** Kein Commit-Hash im Eintrag selbst.
  Hash in die Commit-Message, oder in einem separaten
  Nachzug-Commit nachtragen.

Vorfall: Punkt 84 (2026-10-03), Amend-Zirkel,aufgeloest durch Nachzug-Commit 32bca09.

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
