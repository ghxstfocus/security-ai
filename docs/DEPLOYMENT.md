# Deployment — Homelab Security AI

> Wie das System auf Proxmox aufgesetzt wird: Container,
> Services, Netzwerk, Backups.

## 1. Ziel-Topologie

    Proxmox-Host (pve)
    |
    |-- LXC 101: homelab-security     (192.168.178.116)  [Bestand]
    |-- LXC 102: security-ai          (192.168.178.117)  [dieses Projekt]
    |-- LXC 103: security-tools       (192.168.178.118)  [geplant]
    |-- LXC 104: security-db          (192.168.178.119)  [geplant]
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

    pip install -e ".[dev]"

Oder nur Runtime:

    pip install -e .

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

    cd /opt/security-ai
    source .venv/bin/activate
    python -m apps.security_ai

## 3. Systemd-Service

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

## 4. Netzwerk und Firewall

### 4.1 Feste IP

Der Container hat 192.168.178.117 (statisch, per pct create).

### 4.2 Ports

| Port | Dienst              | Exponiert     |
|------|---------------------|---------------|
| 5000 | Webhook             | nur LAN       |
| 8080 | Dashboard           | nur LAN       |

### 4.3 Capabilities entziehen

In /etc/pve/lxc/102.conf auf dem Host:

    lxc.cap.drop = net_raw net_admin sys_admin sys_module sys_ptrace

Danach:

    pct reboot 102

**Wichtig:** Ohne net_raw kann der Container nicht sniffen.
Scans muessen im separaten security-tools-Container laufen.

### 4.4 Firewall auf dem Host

Falls noetig, eingehende Verbindungen beschraenken:

    # Nur vom Hauptnetz auf Port 5000 + 8080
    iptables -A INPUT -i vmbr0 -s 192.168.178.0/24 -p tcp --dport 5000 -j ACCEPT
    iptables -A INPUT -i vmbr0 -s 192.168.178.0/24 -p tcp --dport 8080 -j ACCEPT
    iptables -A INPUT -i vmbr0 -p tcp --dport 5000 -j DROP
    iptables -A INPUT -i vmbr0 -p tcp --dport 8080 -j DROP

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

    ss -tulpn | grep -E ":5000|:8080"

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
- [ ] SSH nur mit Key (kein Passwort)
- [ ] Telegram-Bot-Token nicht in Logs
- [ ] Audit-Logs schreibgeschuetzt (chattr +a)
- [ ] Backups laufen
- [ ] Service startet bei Reboot

## 10. Naechste Schritte

Nach dem Deployment:

1. Test-Events senden (curl gegen Webhook).
2. Ueberpruefen, dass Audit-Logs geschrieben werden.
3. Sicherstellen, dass Telegram-Alarme ankommen.
4. Dashboard im Browser testen (http://192.168.178.117:8080).
5. Erste Change Requests generieren lassen.

---
Letzte Aktualisierung: 2026-09-20
