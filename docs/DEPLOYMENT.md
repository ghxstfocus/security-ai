# Deployment — Homelab Security AI

> Wie das System auf Proxmox aufgesetzt wird: Container,
> Services, Netzwerk, Backups.

## 1. Ziel-Topologie

    Proxmox-Host (pve)
    |
    |-- LXC 101: homelab-security     (192.168.178.116)  [ruht, unberuehrt]
    |-- LXC 102: security-ai          (192.168.178.117)  [dieses Projekt]
    |
    |-- Host: host_scanner            (auf pve selbst)

## 2. Container 102 — security-ai

### 2.1 Erstellen

    pct create 102 local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst \
      --hostname security-ai \
      --memory 2048 \
      --cores 2 \
      --rootfs local-lvm:8 \
      --net0 name=eth0,bridge=vmbr0,ip=192.168.178.117/24,gw=192.168.178.1 \
      --nameserver 192.168.178.1 \
      --unprivileged 1 \
      --features nesting=1 \
      --onboot 1 \
      --start 1

### 2.2 Basis-Setup im Container

    apt update && apt upgrade -y
    apt install -y python3 python3-pip python3-venv git curl nano sqlite3 \
                   htop tmux tree openssh-server locales
    systemctl enable --now ssh

    # Locale auf UTF-8
    sed -i 's/^# *de_DE.UTF-8 UTF-8/de_DE.UTF-8 UTF-8/' /etc/locale.gen
    locale-gen
    update-locale LANG=de_DE.UTF-8

### 2.3 Projektordner

    mkdir -p /opt/security-ai
    cd /opt/security-ai
    python3 -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip

### 2.4 Dependencies installieren

    .venv/bin/pip install -e ".[dev]"

Oder nur Runtime:

    .venv/bin/pip install -e .

Voraussetzung: `pyproject.toml` enthaelt einen
`[tool.setuptools.packages.find]`-Block mit
`include`/`exclude`. Ohne diesen Block scheitert
`pip install -e .` mit:

    error: Multiple top-level packages discovered
    in a flat-layout

### 2.5 .env anlegen

    cp .env.example .env
    nano .env

Werte setzen:

- SECRET_KEY — zufaelliger String (openssl rand -hex 32)
- DASHBOARD_PASSWORD — starkes Passwort
- WEBHOOK_TOKEN — zufaelliger Token (openssl rand -hex 32)
- TELEGRAM_BOT_TOKEN — von BotFather
- TELEGRAM_CHAT_ID — eigene Chat-ID
- FRITZ_ADDRESS — 192.168.178.1
- FRITZ_USER / FRITZ_PASSWORD — falls gesetzt
- PROXMOX_URL / PROXMOX_TOKEN_* — fuer Proxmox-Zugriff

Dateirechte:

    chmod 600 .env

### 2.6 Testlauf

Manuell starten, um zu sehen, dass alles laeuft:

    cd /opt/security-ai && \
      .venv/bin/python3 -m apps.security_ai

### 2.7 Arbeitsverzeichnis

Alle Service-Aufrufe muessen aus `/opt/security-ai`
erfolgen. Grund:

- `detection/rules.yaml`, `policies/tools.yaml`,
  `core/risk/rules.yaml` werden relativ zum CWD
  geladen.
- `scripts/*` sind Werkzeuge, keine Bibliothek.
  Nur aus `/opt/security-ai` importierbar (siehe
  `docs/WERKZEUGE.md`).

Konsequenz fuer den systemd-Service:

    WorkingDirectory=/opt/security-ai

Konsequenz fuer CLI-Aufrufe:

    cd /opt/security-ai && \
      .venv/bin/python3 scripts/chat_cli.py ...

## 3. Systemd-Service

> Status: geplant, nicht implementiert.
> Es gibt heute keine systemd-Unit security-ai.service.
> Der Orchestrator wird manuell gestartet (siehe
> SECURITY_REVIEW_LOG Punkt 26).

### 3.1 Unit-Datei anlegen

    nano /etc/systemd/system/security-ai.service

Inhalt:

    [Unit]
    Description=Homelab Security AI
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    User=root
    WorkingDirectory=/opt/security-ai
    Environment=PYTHONUNBUFFERED=1
    EnvironmentFile=/opt/security-ai/.env
    ExecStart=/opt/security-ai/.venv/bin/python -m apps.security_ai
    Restart=always
    RestartSec=10
    StandardOutput=journal
    StandardError=journal

    [Install]
    WantedBy=multi-user.target

### 3.2 Aktivieren

    systemctl daemon-reload
    systemctl enable security-ai.service
    systemctl start security-ai.service
    systemctl status security-ai.service

### 3.3 Logs

    journalctl -u security-ai.service -f
    journalctl -u security-ai.service --since "10 minutes ago"

## 3a. Runtime-Abhaengigkeiten (nmap)

nmap ist eine Runtime-Abhaengigkeit von `tools/nmap_scan.py` und
wird NICHT vom Tool selbst installiert. Fehlt das Binary, wirft
`nmap_scan_run` fail-closed einen `ToolError` und der Aufruf wird
nicht ausgefuehrt.

Installation im Container CT102 (security-ai):

    apt update
    apt install -y nmap

Verifikation:

    which nmap
    nmap --version | head -1

Erwartet: `/usr/bin/nmap` und eine Versionszeile (z. B. `Nmap
version 7.93`).

Sandbox-Kontext:
- Profil: `nmap_local` (siehe `tools/nmap_scan.py`)
- Kein Shell (`shell=False`, Argumentliste)
- Timeout 30 s (`subprocess.run(..., timeout=30)`)
- Argument-Whitelist: `-sT`, `-sV`, `-p`, `--top-ports`, `-oX`, `-Pn`, `-n`
- Ziel-Whitelist: `localhost`, `127.0.0.0/8`, `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`
- Erlaubter Scan-Typ: nur `connect` (nutzt `-sT`).
  `syn` (braucht root) und `ping` sind bewusst gesperrt.
- Ausgabe: XML auf stdout (`-oX -`), geparst mit
  `xml.etree.ElementTree`.

Tests:
- Unit: `tests/unit/test_nmap_scan.py` (subprocess gemockt)
- Integration: `tests/integration/test_nmap_real.py`
  (`skipif` kein nmap). Laeuft nur gegen `127.0.0.1`.

## 3b. Lokale KI (Ollama)

Ollama stellt das lokale LLM bereit. Kein Cloud-Zugriff.
Wird von `harness/llm/client.py` per HTTP angesprochen
(`http://127.0.0.1:11434/api/generate`).

### Hardware (CT102)

- 16 GB Disk
- 12 GB RAM
- 4 CPU-Kerne
- Keine GPU -> CPU-Inferenz

### Installation

Ollama nach offizieller Anleitung installieren
(https://ollama.com/download). Nach der Installation:

    systemctl status ollama

### Modelle

Zwei Modelle mit klaren Rollen:

- `llama3.2:3b` (~2,2 GB) — Default.
  Schnell, CPU-tauglich, Antworten in Sekunden.
- `qwen2.5:7b` (~4,7 GB) — Large.
  Tiefere Antworten, aber auf CPU ohne GPU langsam.
  Nur bei Bedarf nutzen.

Installation:

    ollama pull llama3.2:3b
    ollama pull qwen2.5:7b

Pruefen:

    ollama list
    curl -s http://127.0.0.1:11434/api/tags | head -c 300

### Tuning

Bei wenig RAM/CPU (Homelab) sind zwei Ollama-Parameter
wichtig. In `systemctl edit ollama` eintragen:

    [Service]
    Environment="OLLAMA_KEEP_ALIVE=-1"
    Environment="OLLAMA_NUM_PARALLEL=1"

- OLLAMA_KEEP_ALIVE=-1: Modell bleibt im RAM, kein
  Nachladen pro Anfrage.
- OLLAMA_NUM_PARALLEL=1: Nur eine Anfrage gleichzeitig.
  Verhindert RAM-Spikes.

Nach der Aenderung:

    systemctl daemon-reload
    systemctl restart ollama

### Konfiguration der Security AI

In `.env` (siehe `.env.example`):

    OLLAMA_BASE_URL=http://127.0.0.1:11434
    SECURITY_AI_MODEL=llama3.2:3b
    SECURITY_AI_MODEL_LARGE=qwen2.5:7b

Die Werte werden von `core/config.py` gelesen. Bereits
gesetzte Umgebungsvariablen gewinnen.

### Modellwahl nach Hardware

- CPU-only, wenig RAM (< 8 GB): nur `llama3.2:3b` ziehen.
- CPU-only, 12+ GB RAM: beide Modelle moeglich, aber
  `qwen2.5:7b` nur fuer tiefe Fragen.
- GPU vorhanden: `qwen2.5:7b` als Default denkbar.

### Fail-closed-Verhalten

Wenn Ollama nicht erreichbar ist:

- `harness/llm/client.py` wirft `LLMUnavailable`.
- `ChatService.ask` propagiert `LLMError` (fail closed).
- Das CLI faengt den Fehler, gibt "FEHLER: LLM: ..." aus
  und beendet mit Exit 1.
- Kein stiller Fallback, keine erfundene Antwort.

### Was Ollama NICHT darf

- Kein Cloud-Zugriff. Modell laeuft lokal.
- Kein Auto-Pull. Modell-Updates nur explizit.
- Kein Tool-Aufruf aus dem LLM. Es formuliert nur
  Erklaerungen.

## 3c. Dashboard hinter nginx mit TLS

Das Dashboard wird nicht mehr direkt auf 0.0.0.0:5000
betrieben, sondern ausschliesslich ueber einen nginx-
Reverse-Proxy mit TLS. Flask bindet lokal auf 127.0.0.1:5000,
nginx terminiert TLS auf 0.0.0.0:443 und leitet alle Anfragen
per proxy_pass an Flask weiter. Port 80 antwortet nur mit
einem 301-Redirect auf HTTPS.

### 3c.1 Voraussetzungen

- Debian 12 (bookworm), nginx aus dem Standard-Repo
  (Version 1.22.1 oder neuer).
- System-User `security-ai` existiert (UID/GID aus
  `id security-ai`).
- `apps/dashboard/app.py` besitzt einen
  `if __name__ == "__main__":`-Block, der mit
  `host="127.0.0.1", port=5000, debug=False` startet.

### 3c.2 Eigene CA und Server-Zertifikat

Der Ablauf erzeugt eine eigene CA und ein Server-Zertifikat.
Alle privaten Schluessel liegen in `/etc/ssl/private/`, nicht
im Projektverzeichnis und nicht im Git.

CA-Schluessel (600, root:root):

    openssl genrsa -out /etc/ssl/private/security-ai-ca.key 4096
    chmod 600 /etc/ssl/private/security-ai-ca.key
    chown root:root /etc/ssl/private/security-ai-ca.key

CA-Zertifikat (5 Jahre):

    openssl req -x509 -new -nodes \
        -key /etc/ssl/private/security-ai-ca.key \
        -sha256 -days 1825 \
        -subj "/CN=Homelab Security AI Internal CA" \
        -out /etc/ssl/certs/security-ai-ca.crt

Server-Schluessel (640, root:ssl-cert):

    openssl genrsa -out /etc/ssl/private/security-ai.key 4096
    chmod 640 /etc/ssl/private/security-ai.key
    chown root:ssl-cert /etc/ssl/private/security-ai.key

Server-CSR und Zertifikat (2 Jahre), SAN muss die Nutzungsnamen
enthalten:

    openssl req -new \
        -key /etc/ssl/private/security-ai.key \
        -subj "/CN=security-ai.local" \
        -out /tmp/security-ai.csr

    openssl x509 -req \
        -in /tmp/security-ai.csr \
        -CA /etc/ssl/certs/security-ai-ca.crt \
        -CAkey /etc/ssl/private/security-ai-ca.key \
        -CAcreateserial \
        -days 730 -sha256 \
        -extfile <(printf "subjectAltName=DNS:security-ai.local,DNS:security-ai,IP:192.168.178.117,IP:127.0.0.1") \
        -out /etc/ssl/certs/security-ai.crt

    rm -f /tmp/security-ai.csr

Kontrolle der SAN-Eintraege:

    openssl x509 -in /etc/ssl/certs/security-ai.crt -text -noout \
        | grep -A1 "Subject Alternative Name"

### 3c.3 CA im Browser/OS importieren

Das CA-Zertifikat `security-ai-ca.crt` muss einmalig pro Client
in den Browser- oder Betriebssystem-Truststore importiert werden.
Danach zeigt der Browser keine Warnung mehr, weil die Verbindung
ueber eine vertrauenswuerdige CA laeuft.

Der Import erfolgt **nicht** durch Wegklicken der Warnung.
Wer das CA-Zertifikat nicht importieren will, kann das Dashboard
nicht per HTTPS erreichen; HTTP wird nicht angeboten.

Linux (Debian/Ubuntu):

    sudo cp security-ai-ca.crt /usr/local/share/ca-certificates/
    sudo update-ca-certificates

Firefox (eigener Truststore): Einstellungen -> Datenschutz & Sicherheit
-> Zertifikate -> Zertifizierungsstellen -> Importieren.

Windows: `security-ai-ca.crt` doppelklicken, Ablageort
"Lokaler Computer", Zertifikatspeicher "Vertrauenswuerdige
Stammzertifizierungsstellen".

macOS: Keychain-Zugriff -> System -> Zertifikate -> Importieren,
danach im Zertifikat auf "Immer vertrauen" stellen.

### 3c.4 nginx-Konfiguration

Die Konfiguration liegt im Repo unter
`deploy/nginx/security-ai.conf`. Sie wird manuell nach
`/etc/nginx/sites-available/security-ai.conf` kopiert, Symlink nach
`/etc/nginx/sites-enabled/security-ai.conf`. Der Port-80-Block
antwortet nur mit einem Redirect. Der Port-443-Block terminiert
TLS und reicht an Flask weiter. Header aus Flask werden unveraendert
durchgereicht; nginx fuegt **nur** den HSTS-Header hinzu.

Test der Konfiguration vor dem Reload:

    nginx -t

Bei Fehlern bricht `nginx -t` ab; kein Reload ohne sauberen Test.

### 3c.5 systemd-Units

- `security-ai-dashboard.service` startet Flask als User
  `security-ai`, gebunden auf 127.0.0.1:5000.
- nginx laeuft als Standard-Unit `nginx.service` aus dem
  Debian-Paket, ohne Anpassung.
- Der Dashboard-Service benoetigt nginx nicht als harte
  Abhaengigkeit. Faellt nginx aus, ist das Dashboard nicht
  erreichbar; faellt das Dashboard aus, antwortet nginx mit
  502 Bad Gateway. Kein HTTP-Fallback, kein direkter Zugriff.

### 3c.6 Ports (aktualisiert gegenueber § 4.2)

| Port | Dienst              | Bind-Adresse     |
|------|---------------------|------------------|
| 5000 | Flask Dashboard     | 127.0.0.1        |
| 80   | nginx Redirect      | 0.0.0.0          |
| 443  | nginx TLS           | 0.0.0.0          |

Port 8080 wird nicht mehr verwendet.

### 3c.7 Fail closed

- Ist nginx gestoppt, ist das Dashboard nicht erreichbar.
- Ist das Dashboard gestoppt, antwortet nginx mit 502.
- Kein Notausgang, kein HTTP-Fallback, kein direkter
  Flask-Zugriff von aussen.

### 3c.8 Checkliste WEB_SECURITY_CHECKLIST § L

- [x] Dashboard laeuft hinter Reverse-Proxy.
- [x] NICHT direkt ins Internet.
- [x] systemd-Service mit User=, ProtectSystem=strict,
  NoNewPrivileges.
- [x] Binding auf 127.0.0.1 fuer Flask.

## 3d. Systemvoraussetzungen

Zentrale Liste der Pakete und Versionen, die auf CT102
fuer den Betrieb von Homelab Security AI notwendig sind.
Getestet mit den unten genannten Versionen; keine
Versions-Pins — ein apt-Upgrade soll die Doku nicht
brechen.

### 3d.1 Basis

- Debian 12 (bookworm).
- Python 3.11 (Systempaket `python3.11` + `python3.11-venv`).
- venv unter `/opt/security-ai/.venv`.
- `util-linux` (Standard): liefert `runuser` fuer
  Deployment-Skripte, die als `security-ai` laufen.

### 3d.2 apt-Pakete (Zweck)

- `nginx` — Reverse-Proxy mit TLS (§3c).
- `openssl` — CA und Server-Zertifikat (§3c.2).
- `sqlite3`, `libsqlite3-0` — Datenhaltung.
- `nmap` — Runtime fuer `tools/nmap_scan.py` (§3a).
- `ca-certificates`, `ssl-cert` — TLS-Vertrauen,
  Gruppe `ssl-cert` fuer Server-Key-Owner.

### 3d.3 Python-Abhaengigkeiten

Die Runtime-Abhaengigkeiten stehen in `pyproject.toml`
unter `[project].dependencies`:
`flask`, `requests`, `psutil`, `PyYAML`.

Fussnote: `psutil` und `PyYAML` sind deklariert, werden
aber heute im Code nicht importiert. Sie bleiben als
Vorbereitung fuer spaetere Phasen.

Optionale Abhaengigkeiten (`scapy`, `fritzconnection`,
`docker`) sind in `pyproject.toml` unter
`[project.optional-dependencies].extras` deklariert,
aber **nicht installiert**. Sie gehoeren zu spaeteren
Phasen (Host-Scanner, Fritz!Box-Anbindung, Docker-Status).

Installation: siehe §2.4.

### 3d.4 systemd-Unit

- `security-ai-dashboard.service` (aus
  `deploy/systemd/`), laeuft als `security-ai`,
  bindet auf `127.0.0.1:5000` (§3c.5).
- nginx als Debian-Standard-Unit `nginx.service`
  ohne Anpassung.

Nach Aenderungen an Python-Code oder
Jinja-Templates: `systemctl restart
security-ai-dashboard`. Ein reload reicht
nicht, weil gunicorn Templates nicht neu
laedt (kein `--preload`, kein `--reload`).

Entwicklungs-Werkzeuge (Tests, Lint, Typen):

    .venv/bin/pip install -e .[dev]

Enthaelt pytest, pytest-cov, ruff, mypy.

### 3d.5 Neuaufbau in Kurzform

    apt install nginx openssl sqlite3 nmap ca-certificates ssl-cert python3.11 python3.11-venv
    git clone git@github.com:ghxstfocus/security-ai.git /opt/security-ai
    cd /opt/security-ai
    python3.11 -m venv .venv
    .venv/bin/pip install -e .
    cp .env.example .env  # SECRET_KEY eintragen
    useradd --system --no-create-home --home /opt/security-ai --shell /usr/sbin/nologin security-ai
    chown security-ai:security-ai audit-logs data
    cp deploy/systemd/security-ai-dashboard.service /etc/systemd/system/
    systemctl daemon-reload && systemctl enable --now security-ai-dashboard
    cp deploy/nginx/security-ai.conf /etc/nginx/sites-available/security-ai.conf
    ln -s /etc/nginx/sites-available/security-ai.conf /etc/nginx/sites-enabled/
    nginx -t && systemctl reload nginx

Details zu CA, Zertifikaten und Cookie-Flags in §3c.
Keine Secrets in dieser Datei.


## 3e. Migrationspflicht

> Produktionsstart (Punkt 16, seit 2026-09-27):
> `pip install -e .[prod]` installiert gunicorn.
> Der Dashboard-Start laeuft ueber gunicorn
> (deploy/gunicorn.conf.py), nicht mehr ueber den
> Flask dev-Server. `ExecStart` der systemd-Unit
> entsprechend angepasst.

Seit 3.6.15a traegt apply_migrations jede angewandte
Migration in schema_migrations ein. Beim App-Start prueft
check_schema_version (Fix D), ob die DB-Version zur
hoechsten Migrationsdatei passt. Bei Abweichung
(DB < Datei) verweigert der App-Start (Fail closed).

Reihenfolge (verbindlich, nicht optional):

  1. ExecStartPre: init_db.py --no-principal migriert.
  2. App-Start: create_app mit check_schema=True prueft.

Das Unit-File deploy/systemd/security-ai-dashboard.service
enthaelt die ExecStartPre-Zeile. Nach jedem git pull, der
data/migrations/*.sql aendert, Unit neu kopieren:

    cp /opt/security-ai/deploy/systemd/security-ai-dashboard.service \
       /etc/systemd/system/security-ai-dashboard.service
    systemctl daemon-reload
    systemctl restart security-ai-dashboard

Verifikation:

    sqlite3 /opt/security-ai/data/inventory.db \
      "SELECT MAX(version) FROM schema_migrations;"

Der Wert muss der hoechsten Datei-Nummer in
data/migrations/ entsprechen (heute 8).

### WorkingDirectory (Punkt 2, 2026-09-26)

Das systemd-Unit setzt `WorkingDirectory=/opt/security-ai`.
Grund: audit-logs/ und detection/rules.yaml werden
relativ zum CWD gelesen. Ohne WorkingDirectory wuerde
der Service audit-logs/ im systemd-Default-CWD suchen
und fail closed verweigern.

Pruefen mit:

    systemctl show security-ai-dashboard -p WorkingDirectory

Erwartet: WorkingDirectory=/opt/security-ai.

Hinweis Version 1: 0001 existiert nicht als Datei.
Die Luecke ist historisch (Vor-Migrations-Aera).

Hinweis Downgrade: Wenn die Code-Version aelter ist
als die DB-Version (DB > Datei), warnt der App-Start
(Schema-Version DB > Datei). Kein Fehler, aber ein
Hinweis, dass das Deployment nicht konsistent ist.
Downgrade der DB ist nicht automatisiert; im Zweifel
Backup einspielen.


## 4. Netzwerk und Firewall

### 4.1 Feste IP

Der Container hat 192.168.178.117 (statisch, per pct create).

### 4.2 Ports

| Port | Dienst              | Bind-Adresse     | Exponiert |
|------|---------------------|------------------|-----------|
| 5000 | Flask Dashboard     | 127.0.0.1        | lokal     |
| 80   | nginx Redirect      | 0.0.0.0          | nur LAN   |
| 443  | nginx TLS           | 0.0.0.0          | nur LAN   |

### 4.3 Capabilities entziehen

In /etc/pve/lxc/102.conf auf dem Host:

    lxc.cap.drop = net_raw net_admin sys_admin sys_module sys_ptrace

Danach:

    pct reboot 102

**Wichtig:** Ohne net_raw kann der Container nicht sniffen.
Scans muessen im separaten security-tools-Container laufen.

### 4.4 Firewall auf dem Host

Falls noetig, eingehende Verbindungen beschraenken:

> Beispiel. Keine automatische Anwendung.
> Diese Regeln sind Vorlage, nicht Skript.
> Reihenfolge beachten: DROP vor ACCEPT fuer
> dasselbe Ziel hebt sich auf.

    # HTTP/HTTPS aus dem Hauptnetz
    iptables -A INPUT -i vmbr0 -s 192.168.178.0/24 -p tcp --dport 80  -j ACCEPT
    iptables -A INPUT -i vmbr0 -s 192.168.178.0/24 -p tcp --dport 443 -j ACCEPT

    # Dashboard-Port 5000 wird NICHT per Host-Firewall
    # freigegeben. Flask bindet auf 127.0.0.1; LAN-Verkehr
    # erreicht den Dienst nicht, unabhaengig von iptables.
    # Wer den Dienst versehentlich auf 0.0.0.0 bindet,
    # sieht das in `ss -tulpn | grep :5000` (siehe §7).

## 5. Backups

### 5.1 Was wird gesichert

- /opt/security-ai/data/ — SQLite-DB, Migrationen
- /opt/security-ai/changes/ — Change Requests
- /opt/security-ai/audit-logs/ — Audit-Trail
- /opt/security-ai/.env — Secrets (verschluesselt!)
- /etc/systemd/system/security-ai.service

### 5.2 Backup-Skript

    nano /opt/security-ai/scripts/backup.sh

Inhalt:

    #!/bin/bash
    set -e
    BACKUP_DIR="/var/backups/security-ai"
    DATE=$(date +%Y-%m-%d_%H-%M)
    mkdir -p "$BACKUP_DIR"
    tar -czf "$BACKUP_DIR/security-ai-$DATE.tar.gz" \
        -C /opt/security-ai \
        data changes audit-logs .env pyproject.toml
    find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
    echo "Backup erstellt: $BACKUP_DIR/security-ai-$DATE.tar.gz"

Ausfuehrbar machen:

    chmod +x /opt/security-ai/scripts/backup.sh

### 5.3 Cron

    crontab -e

Zeile hinzufuegen:

    0 3 * * * /opt/security-ai/scripts/backup.sh

## 6. Updates

### 6.1 System-Updates

    apt update && apt upgrade -y

### 6.2 Python-Dependencies

    cd /opt/security-ai
    source .venv/bin/activate
    pip install --upgrade -e ".[dev]"

### 6.3 Code-Updates

    cd /opt/security-ai
    git pull
    systemctl restart security-ai.service

## 7. Monitoring

### 7.1 Service-Status

    systemctl status security-ai.service

### 7.2 Logs

    journalctl -u security-ai.service -n 50 --no-pager

### 7.3 Ressourcen

    htop
    df -h
    free -m

## 8. Troubleshooting

### Service startet nicht

    systemctl status security-ai.service
    journalctl -u security-ai.service -n 100 --no-pager

### Port belegt

    ss -tulpn | grep -E ':80|:443|:5000'

`:5000` muss auf `127.0.0.1:5000` enden, nicht auf `0.0.0.0:5000`.

### Datenbank-Fehler

    sqlite3 /opt/security-ai/data/homelab.db "PRAGMA integrity_check;"

### Locale-Probleme

    locale
    # Falls LANG=C:
    update-locale LANG=de_DE.UTF-8

## 9. Sicherheit nach Deployment

Checkliste:

- [ ] .env hat chmod 600
- [ ] Capabilities in 102.conf gesetzt
- [ ] Firewall-Regeln aktiv
- [x] SSH nur mit Key (kein Passwort) -- 2026-09-28
- [ ] Telegram-Bot-Token nicht in Logs
- [ ] Audit-Logs schreibgeschuetzt (chattr +a)
- [ ] Backups laufen
- [ ] Service startet bei Reboot

## 10. Naechste Schritte

Nach dem Deployment:

1. Test-Events senden (curl gegen Webhook).
2. Ueberpruefen, dass Audit-Logs geschrieben werden.
3. Sicherstellen, dass Telegram-Alarme ankommen.
4. Dashboard im Browser testen (https://security-ai.local/).
5. Erste Change Requests generieren lassen.

---
Letzte Aktualisierung: 2026-09-23
