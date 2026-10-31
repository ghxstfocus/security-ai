# Homelab Security AI

Ein lokales Security-System fuer das eigene
Homelab. Deterministische Detection, RBAC,
Audit, Human-in-the-Loop. Kein Cloud-Zwang.
Kein LLM in den Entscheidungen.

## Warum es das gibt

KI ist dann wertvoll, wenn sie dort eingesetzt
wird, wo sie hilft: Erklaerungen, Zusammen-
fassungen, Chat. Sie ist dann gefaehrlich, wenn
sie Entscheidungen trifft, die schnell,
nachvollziehbar und sicher sein muessen.

Dieses Projekt zieht die Linie bewusst:
Deterministische Detection, Risk und Policy
ueberall dort, wo Sicherheit zaehlt. Das LLM
nur dort, wo es erklaert.

Der Core ist das BIOS des Systems: basal,
deterministisch, immer da. Er entscheidet
nicht, er liefert Zustand. Er ist auch die
Bridge zu allen Geraeten und Diensten und
der Anker, an dem jede Aktion haengt.

Der Mensch bleibt die letzte Instanz.

## Wie es aussieht

    +-------------------------------------------+
    |  Mensch (letzte Instanz)                  |
    +-------------------------------------------+
                  |               ^
                  v               |
    +-------------------------------------------+
    |  Admin AI (Cloud)   |   Kunden-KI (Cloud) |
    |  Sicherheit         |   Mitarbeiter       |
    |  asynchron, Vorschlaege, Change Requests  |
    +-------------------------------------------+
                  |               ^
                  v               |
    +-------------------------------------------+
    |  CORE (lokal, deterministisch, 24/7)      |
    |  Watcher, Detektoren, Services, Audit     |
    +-------------------------------------------+
                  |               ^
                  v               |
    +-------------------------------------------+
    |  Geraete, Netz, Systeme, externe Dienste  |
    +-------------------------------------------+

## Was der Core heute kann

- Netzwerk-Ueberwachung ueber die Fritz!Box.
- Deterministische Detection mit sechs Regeln.
- Risk Engine, nachvollziehbar und reproduzierbar.
- Alarme per ntfy (self-hosted, Tailscale).
- RBAC: Rollen, Permissions, Sessions.
- Web-Dashboard mit RBAC und strikter CSP.
- Approval Queue und Change Requests.
- Append-only Audit.
- Ueber 1200 Tests, alle gruen.

## Was es nicht tut

- Keine autonomen Firewall-Aenderungen.
- Kein Auto-Block ohne Freigabe.
- Kein Cloud-Zwang.
- Kein LLM in Entscheidungen.
- Kein Selbst-Update ohne Change Request.

## Was kommen soll

- Host-Scanner (Phase 3.8).
- Admin AI (Cloud, Pflicht fuer Sicherheitsnutzung).
- Kunden-KI (baut auf der Admin AI auf).
- Data Connectors (HR, CRM, Tickets).
- Physische Sicherheit (Phase 10).
- Ganzheitliche Korrelation (Phase 11).

## Umgebung

- Container: CT102 auf Proxmox, Hostname security-ai,
  IP 192.168.178.117, Tailscale 100.116.205.98.
- Projektordner: /opt/security-ai.
- GitHub: git@github.com:ghxstfocus/security-ai.git
  (privat, Branch main).
- Debian 12, Python 3.11, pytest 9.1.1 (venv).
- venv-Python: /opt/security-ai/.venv/bin/python3.
- Tests aus CWD /opt/security-ai (Regel-Dateien
  werden relativ zum CWD geladen).
- Zugriff Dashboard: https://security-ai (Tailnet).

## Wo man liest

- docs/STATUS.md - aktueller Stand (HEAD, Tests,
  naechster Block).
- docs/ROADMAP.md - Phasen und Ausblick.
- docs/adr/ - Design-Entscheidungen.
- docs/SECURITY_LOG.md - Sicherheits-Entscheidungen.
- docs/CONVENTIONS.md - projektspezifische Konventionen.
- docs/ARCHITECTURE.md - technische Schichten.
- docs/DEPLOYMENT.md - Installation und Betrieb.
- docs/SECURITY.md - Threat Model und Guardrails.
- PROJECT_VISION.md - die grosse Vision.
- CHANGELOG.md - chronologische Aenderungen.

