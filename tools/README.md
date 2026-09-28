# tools

Konkrete Tools, die der Harness aufruft. Jedes Tool deklariert:
Level, Sandbox-Profil, erlaubte Parameter.

## fritzbox_watcher.py

Producer fuer device_presence/device_offline. Liest die
Host-Liste der Fritz!Box via TR-064, vergleicht mit dem
letzten Lauf, schreibt Events (JSONL, append-only) nach
data/events-YYYY-MM-DD.jsonl. Kein Tool im Sinne der
ToolRegistry (kein func(**args), kein Level), sondern ein
eigenstaendiger Producer, der per systemd-Timer laeuft.

identifier=MAC (stabil ueber DHCP). Fail closed:
Exit 0=OK, 1=Fritz!Box nicht erreichbar,
2=Credentials fehlen, 3=Schreibfehler.
