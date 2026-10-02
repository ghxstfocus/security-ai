# ntfy — Benachrichtigungssystem (Punkt 77)

Self-hosted Push-Benachrichtigungen fuer Alarme.
Laeuft auf dem **Proxmox-Host**, nicht in CT102
(Entscheidung des Nutzers, siehe SECURITY_REVIEW_LOG
Punkt 77).

## Warum ntfy

- Self-hosted, kein Dritter.
- HTTP POST, keine Bot-Protokoll-Komplexitaet.
- Android-App verfuegbar.
- Erreichbar ueber Tailscale (kein Port-Forwarding).

## Voraussetzungen

- Proxmox-Host mit systemd.
- Tailscale laeuft auf dem Host.
- Ziel: ntfy bindet an die Tailscale-IP des Hosts,
  Port 2586.

## 1. Installation auf dem Host

Als root auf dem Proxmox-Host:

    apt install curl gnupg
    curl -fsSL https://archive.ntfy.sh/apt/KEY.gpg \\
        | gpg --dearmor -o /usr/share/keyrings/ntfy.gpg
    echo "deb [signed-by=/usr/share/keyrings/ntfy.gpg] \\
        https://archive.ntfy.sh/apt/ stable main" \\
        > /etc/apt/sources.list.d/ntfy.list
    apt update
    apt install ntfy

Pruefen:

    ntfy --version
    systemctl status ntfy

Der Debian-Installer legt einen `ntfy`-User an
und installiert `ntfy.service`.

## 2. systemd-Unit anpassen (Restart=always)

Der Standard-Unit-Datei fehlt `Restart=always`
(der Default ist `Restart=on-failure`, was bei
einem sauberen Exit nicht greift).

    systemctl edit ntfy.service

Im Override-Block ergaenzen:

    [Service]
    Restart=always
    RestartSec=5

Neuladen:

    systemctl daemon-reload
    systemctl restart ntfy
    systemctl status ntfy

Verifikation, dass `Restart=always` gesetzt ist:

    systemctl show ntfy.service --property=Restart

Erwartung: `Restart=always`.

## 3. Konfiguration /etc/ntfy/server.yml

Tailscale-IP des Hosts ermitteln:

    tailscale ip -4

    listen-http: "100.x.y.z:2586"
    base-url: "http://100.x.y.z:2586"
    cache-file: "/var/cache/ntfy/cache.db"
    auth-file: "/var/lib/ntfy/user.db"
    auth-default-access: "deny-all"
    enable-signup: false

Wichtig: `listen-http` auf die **Tailscale-IP**,
nicht auf `0.0.0.0`. Damit ist ntfy nur aus dem
Tailnet erreichbar.

Neustart:

    systemctl restart ntfy
    ss -ltnp | grep 2586

## 4. Topic und Tokens anlegen

Topic: langer zufaelliger String, 32 Zeichen.

    openssl rand -base64 24 | tr -d '=+/' | cut -c1-32

Notieren. Nicht im Repo, nicht im Chat.

Tokens anlegen (ntfy-CLI):

    ntfy user add --role=admin admin
    ntfy token add admin --label=publish-ct102
    ntfy token add admin --label=read-handy

Die Token-Werte werden beim Anlegen ausgegeben.
Jeder nur einmal sichtbar.

Topic-Zugriff:

    ntfy access admin "<topic>" read-write

## 5. .env in CT102

In /opt/security-ai/.env ergaenzen:

    NTFY_URL=http://100.x.y.z:2586
    NTFY_TOPIC=<32-Zeichen-Topic>
    NTFY_TOKEN=<publish-token>

Rechte pruefen: `.env` bleibt 600 root:root.

## 6. Services neu starten

Der Event-Reader liest die Env bei jedem Timer-Lauf
neu (systemd `EnvironmentFile`). Also reicht es,
den naechsten Lauf abzuwarten. Fuer einen sofortigen
Test: manueller Aufruf, siehe Schritt 7.

## 7. Test

Direktaufruf des Tools in CT102:

    cd /opt/security-ai
    /opt/security-ai/.venv/bin/python3 -c "
    import sys; sys.path.insert(0, '.')
    from tools.notify_ntfy import notify_ntfy_run
    print(notify_ntfy_run('Test', 'Nachricht von CT102', 'INFO'))
    "

Erwartung:
- Rueckgabe mit `ok: True`, `source: ntfy`.
- Android-App zeigt die Benachrichtigung.

## 8. Android-Push

- ntfy-App aus dem Play Store oder F-Droid.
- Topic abonnieren, mit dem Read-Token.
- Bei F-Droid (ohne Google-Dienste): Background-Push
  per FCM funktioniert nicht. Die App nutzt dann
  eine dauerhafte WebSocket-Verbindung im
  Vordergrund (Battery-Optimierung deaktivieren).
- Bei Play-Store-Variante: Push via FCM. Der Inhalt
  geht durch Google-Server. Opt-out nur mit der
  F-Droid-Variante moeglich.

## 9. Fallback

Wenn ntfy nicht erreichbar ist, wirft
`notify_ntfy_run` eine `ToolError`. Der AgentLoop
faengt sie, auditiert `execution_status=ERR`, macht
weiter. Der Alarm bleibt im Audit-Log nachvollziehbar.

Telegram (Punkt 76) bleibt als optionaler Fallback
offen.

## 10. Troubleshooting

- `Restart=always` pruefen mit `systemctl show`.
- ntfy-Log: `journalctl -u ntfy -f`.
- Token-Fehler: `ntfy token list`.
- Topic-Fehler: `ntfy access` listet Zugriffe.
- Erreichbarkeit vom Handy: `curl http://100.x.y.z:2586/v1/health`.

