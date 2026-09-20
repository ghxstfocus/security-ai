# Berechtigungen — Level 0 bis 5

> Jedes Tool hat ein Berechtigungs-Level. Was nicht explizit
> erlaubt ist, ist verboten. Fail closed.

## 1. Überblick

| Level | Name              | Human-in-the-Loop  | Beispiel                              |
|-------|-------------------|--------------------|---------------------------------------|
| 0     | READ / LOW RISK   | AUTOMATIC          | read_logs, get_devices                |
| 1     | SECURITY ACTION   | AUTOMATIC          | nmap (authorized), telegram_alert     |
| 2     | REVIEW REQUIRED   | REVIEW             | groesserer Scan, Datenexport          |
| 3     | CHANGE REQUIRED   | REVIEW             | Konfigurationsvorschlag               |
| 4     | APPROVAL REQUIRED | APPROVAL           | Firewall-Aenderung, Geraet blocken    |
| 5     | FORBIDDEN         | (immer blockiert)  | Guardrails aendern, Audit deaktivieren |

## 2. Level 0 — READ / LOW RISK

**Was erlaubt ist:**

- Logs lesen
- Geraete-Liste abrufen
- Whitelist pruefen (nur lesen)
- Datenbank lesen (nur SELECT)
- Docker-Status abrufen
- Proxmox-Status abrufen

**Was NICHT erlaubt ist:**

- Schreiben in irgendeine Datei ausser Audit
- Aenderungen an Systemen
- Netzwerkzugriffe nach aussen

**Human-in-the-Loop:** AUTOMATIC

**Sandbox:** read_only

**Beispiele fuer Tools:**

- read_logs
- get_devices
- whitelist_check
- db_query (nur SELECT)
- docker_inspect
- proxmox_status

## 3. Level 1 — SECURITY ACTION

**Was erlaubt ist:**

- Alarm senden (Telegram)
- Nmap-Scan gegen autorisierte Hosts
- Netzwerk-Sniffing (nur auf autorisierten Interfaces)

**Was NICHT erlaubt ist:**

- Scans ausserhalb autorisierter Netze
- Schreiben in Produktivsysteme
- Aenderungen an Konfiguration

**Human-in-the-Loop:** AUTOMATIC

**Sandbox:** tool-spezifisch

**Beispiele fuer Tools:**

- telegram_alert
- nmap_scan (nur autorisierte Ziele)
- network_sniff (nur auf konfiguriertem Interface)

**Voraussetzungen:**

- scope_guard prueft Ziel-IP gegen autorisierte Netze
- Bei Verstoss: Blockiert und auditiert

## 4. Level 2 — REVIEW REQUIRED

**Was erlaubt ist:**

- Groessere Scans (mehrere Hosts)
- Datenexport in Dateien
- Erstellung von Reports

**Was NICHT erlaubt ist:**

- Aenderungen an Systemen
- Schreibende Zugriffe auf Produktivdaten

**Human-in-the-Loop:** REVIEW

**Ablauf:**

1. Tool-Aufruf erreicht Loop
2. Loop pausiert
3. Change Request wird erstellt
4. Mensch prueft im Dashboard
5. Mensch entscheidet: APPROVED / REJECTED
6. Loop setzt fort oder beendet sich

**Beispiele fuer Tools:**

- nmap_scan_subnet
- export_report
- generate_change_proposal

## 5. Level 3 — CHANGE REQUIRED

**Was erlaubt ist:**

- Konfigurationsaenderungen vorschlagen
- Code-Aenderungen vorbereiten (in changes/)
- Tests fuer Changes erstellen

**Was NICHT erlaubt ist:**

- Direkte Anwendung von Aenderungen
- Schreibzugriff auf Produktivsysteme

**Human-in-the-Loop:** REVIEW

**Ablauf:**

1. Admin AI erstellt Change Request
2. Change Request landet in changes/
3. Mensch prueft Code + Tests + Rollback
4. Mensch entscheidet

**Beispiele fuer Tools:**

- propose_config_change
- propose_code_change
- create_test_for_change

## 6. Level 4 — APPROVAL REQUIRED

**Was erlaubt ist (nur nach expliziter Freigabe):**

- Firewall-Regeln aendern
- Geraet blocken
- Produktivkonfiguration anpassen
- Dienst neustarten
- Deploy durchfuehren

**Human-in-the-Loop:** APPROVAL

**Ablauf:**

1. Change Request wird vorbereitet
2. Mensch bekommt Nachricht (Telegram + Dashboard)
3. Mensch liest Details, Rollback, Tests
4. Mensch gibt frei oder lehnt ab
5. Bei Freigabe: Change wird angewendet
6. Bei Ablehnung: Change wird verworfen
7. Alles wird auditiert

**Beispiele fuer Tools:**

- firewall_rule_change
- block_device
- deploy_change
- restart_service

**Wichtig:**

- Kein automatisches Ausfuehren.
- Kein Timeout, der automatisch freigibt.
- Bei Zweifel: nichts tun.

## 7. Level 5 — FORBIDDEN

**Immer blockiert. Keine Ausnahmen.**

**Was verboten ist:**

- Guardrails aendern
- Permission-System aendern
- Audit-System deaktivieren oder manipulieren
- Eigene Policies aendern
- System-Shell-Befehle ausfuehren
- Netzwerk-Scope erweitern
- Credentials aendern
- Sich selbst updaten

**Human-in-the-Loop:** (keine — immer blockiert)

**Ablauf:**

1. Tool-Aufruf erreicht Loop
2. Level 5 wird erkannt
3. Exception wird geworfen
4. Audit-Eintrag: FORBIDDEN
5. Alarm an Mensch (Telegram + Dashboard)
6. Kein weiterer Schritt

**Beispiele fuer Tools:**

- modify_guardrails
- modify_permissions
- disable_audit
- execute_shell
- modify_scope
- self_update

## 8. Tool-Registrierung

Jedes Tool wird in der Tool Registry registriert mit:

    Tool(
        name="nmap_scan",
        level=Level.SECURITY_ACTION,
        sandbox_profile="nmap_local",
        func=tools.nmap_scan.run,
        allowed_args={"target", "ports", "scan_type"},
        description="Nmap-Scan gegen autorisierte Hosts",
        version="1.0.0",
    )

**Regeln:**

- Kein Tool ohne Level.
- Kein Tool ohne Sandbox-Profil (ausser Level 5, das hat keins).
- Kein Tool mit unbeschraenkten Parametern.
- Jedes Tool hat eine Version.

## 9. Policy-Engine

Die Policy Engine prueft jeden Tool-Aufruf gegen die Policies in
policies/permissions.yaml.

Beispiel:

    tools:
      read_logs:
        level: 0
        sandbox: read_only
      telegram_alert:
        level: 1
        sandbox: no_network_except_telegram
      nmap_scan:
        level: 1
        sandbox: nmap_local
        allowed_targets: authorized
      firewall_change:
        level: 4
        sandbox: none
      modify_policy:
        level: 5

**Regel:** Was nicht in der Policy steht, ist verboten.

## 10. Eskalationspfad

Wenn ein Tool mehr Rechte braucht:

1. **Nicht** einfach Level hochsetzen.
2. Change Request erstellen.
3. Mensch prueft.
4. Bei Freigabe: Policy wird angepasst.
5. Alles auditiert.

**Faustregel:** Lieber zu wenig Rechte als zu viel.

## 11. Audit-Anforderungen

Jeder Tool-Aufruf wird auditiert mit:

- Audit-ID
- Zeitstempel
- Agent (security_ai, admin_ai, host_scanner)
- Tool-Name
- Level
- Argumente (gehasht)
- Policy-Ergebnis (ALLOWED / REVIEW / APPROVAL / FORBIDDEN)
- Ausfuehrungsstatus
- Dauer
- Ergebnis (gehasht)

## 12. Zusammenfassung

| Frage                                | Antwort                  |
|--------------------------------------|--------------------------|
| Wer darf Tools aufrufen?             | Nur der Harness          |
| Wer entscheidet ueber Level?         | Die Policy Engine        |
| Wer kann Level aendern?              | Nur der Mensch           |
| Was passiert bei Level 5?            | Sofortige Blockade       |
| Was passiert bei Level 4?            | Warten auf Freigabe      |
| Was passiert bei Level 0-1?          | Automatisch              |
| Was passiert bei Level 2-3?          | Review vor Ausfuehrung   |

---
Letzte Aktualisierung: 2026-09-20
