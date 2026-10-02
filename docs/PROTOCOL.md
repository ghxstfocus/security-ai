# Föderationsprotokoll — MCP-Erweiterung für Security AIs

> Standardisiertes Protokoll für die Kommunikation zwischen
> Security AIs (lokal, pro Netzwerk) und der Admin AI
> (zentral, Cloud oder On-Prem).

## 1. Grundprinzip

Jede Nachricht ist:

- signiert (HMAC oder asymmetrisch)
- versioniert (Protokoll-Version)
- adressiert (network_id, event_id, change_id)
- idempotent (mehrfache Zustellung erlaubt)

Keine Seite vertraut der anderen blind. Jede Aktion wird auf
beiden Seiten auditiert.

## 2. Transport

- HTTPS mit gegenseitiger TLS-Authentifizierung (mTLS)
- Push von Security AI nach Admin AI für Events
- Pull von Admin AI nach Security AI für Changes
- Fallback: signierte JSON-Dateien über SFTP, wenn keine
  dauerhafte Verbindung möglich ist

## 3. Nachrichtenformat

### 3.1 Event (Security AI nach Admin AI)

    {
      "protocol": "mcp-security/1.0",
      "message_id": "MSG-2026-09-20-00042",
      "network_id": "homelab-ct101",
      "timestamp": "2026-09-20T22:15:00Z",
      "type": "event",
      "payload": {
        "event_id": "EVT-2026-09-20-00123",
        "event_type": "unknown_device",
        "severity": "WARNING",
        "data": {
          "identifier": "192.168.178.87",
          "entity_name": "Unknown-Device",
          "network_type": "Hauptnetz",
          "first_seen": "2026-09-20T22:14:32Z"
        }
      },
      "signature": "hmac-sha256:..."
    }

### 3.2 Change Request (Admin AI nach Security AI)

    {
      "protocol": "mcp-security/1.0",
      "message_id": "MSG-2026-09-20-00043",
      "network_id": "homelab-ct101",
      "timestamp": "2026-09-20T22:16:00Z",
      "type": "change_request",
      "payload": {
        "change_id": "CHG-2026-00042",
        "title": "SSH: Passwort-Auth deaktivieren",
        "risk_level": 2,
        "problem": "SSH erlaubt Passwort-Authentifizierung.",
        "evidence": [
          "/etc/ssh/sshd_config: PasswordAuthentication yes",
          "auth.log: 47 fehlgeschlagene Logins aus 203.0.113.5"
        ],
        "proposed_change": {
          "file": "/etc/ssh/sshd_config",
          "diff": "-PasswordAuthentication yes\n+PasswordAuthentication no"
        },
        "rollback": {
          "file": "/etc/ssh/sshd_config",
          "diff": "-PasswordAuthentication no\n+PasswordAuthentication yes"
        },
        "tests": [
          "ssh -o PreferredAuthentications=password user@host (erwartet: fail)",
          "ssh -i key user@host (erwartet: ok)"
        ],
        "requires_approval": true
      },
      "signature": "hmac-sha256:..."
    }

### 3.3 Approval Response (Human nach Admin AI)

    {
      "protocol": "mcp-security/1.0",
      "message_id": "MSG-2026-09-20-00044",
      "network_id": "homelab-ct101",
      "timestamp": "2026-09-20T22:30:00Z",
      "type": "approval_response",
      "payload": {
        "change_id": "CHG-2026-00042",
        "decision": "approved",
        "approved_by": "human_admin",
        "comment": "Sieht gut aus. Rollback vorhanden."
      },
      "signature": "hmac-sha256:..."
    }

## 4. Statusmodell für Change Requests

    DRAFT           -> {TESTING, PENDING_REVIEW, REJECTED, CANCELLED}
    TESTING         -> {PENDING_REVIEW, REJECTED, CANCELLED}
    PENDING_REVIEW  -> {APPROVED, REJECTED, CANCELLED}
    APPROVED        -> {DEPLOYED, CANCELLED}
    DEPLOYED        -> {ROLLED_BACK}
    ROLLED_BACK     -> {}
    REJECTED        -> {}
    CANCELLED       -> {}

CANCELLED = Antragsteller zieht zurueck.
REJECTED  = Reviewer lehnt ab.
Die beiden Zustände sind nicht austauschbar.

Jeder Übergang wird auditiert. Kein Status kann übersprungen werden.
Kein Übergang aus APPROVED nach REJECTED: wer freigegeben hat,
kann den Change nur noch deployen oder vom Antragsteller
zurückziehen lassen (CANCELLED).

## 5. Authentifizierung

- Jedes Netzwerk hat eigene Credentials (kein Shared Secret).
- Empfohlen: mTLS mit pro Netzwerk eigenem Client-Zertifikat.
- Jede Nachricht zusätzlich signiert (HMAC mit Netzwerk-Schlüssel).
- Replay-Schutz über message_id und timestamp (max. 5 Min. Drift).

## 6. Audit-Anforderungen

Auf beiden Seiten wird protokolliert:

- Jede gesendete Nachricht
- Jede empfangene Nachricht
- Jede akzeptierte/abgelehnte Signatur
- Jede Statusänderung eines Change Requests

Format: append-only JSONL, ein Eintrag pro Zeile.

## 7. Versionierung

- Protokoll-Version ist Teil jeder Nachricht.
- Breaking Changes erhöhen die Major-Version.
- Security AI und Admin AI müssen nicht dieselbe Version
  haben — sie müssen kompatibel sein.

## 8. Erweiterbarkeit

Das Protokoll ist bewusst minimal. Erweiterungen sind möglich für:

- Endpoint-Events
- Cloud-Infrastruktur
- OT/ICS-Monitoring

Erweiterungen müssen:

- abwärtskompatibel sein
- im payload-Objekt liegen
- versioniert werden

## 9. Referenzimplementierung

- Security AI: apps/security_ai/
- Admin AI: apps/admin_ai/
- Protokoll-Client: core/protocol/

---
Letzte Aktualisierung: 2026-10-02
