"""
Audit-Writer — append-only JSONL-Log aller Aktionen.

Regeln:
- Append-only. Kein UPDATE, kein DELETE.
- Eine Zeile pro Eintrag (JSONL).
- Datei pro Tag: audit-logs/YYYY-MM-DD.jsonl
- Bei Fehler: Fail closed (Exception), niemals still schlucken.

Verwendung:

    from harness.audit.writer import AuditWriter, AuditEntry

    writer = AuditWriter(base_dir="audit-logs")

    entry = AuditEntry(
        agent="security_ai",
        tool="nmap_scan",
        args={"target": "192.168.178.1"},
        policy_result="ALLOWED",
        permission_level=1,
        execution_status="OK",
        duration_ms=342,
    )
    writer.write(entry)
"""
from __future__ import annotations

import hashlib
import json
import os
import pwd
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, UTC
from pathlib import Path
from typing import Any

# Erlaubte Werte für policy_result
VALID_POLICY_RESULTS = frozenset({
    "ALLOWED",
    "REVIEW",
    "APPROVAL_REQUIRED",
    "FORBIDDEN",
    "DENIED",
})


class AuditError(Exception):
    """Basis-Exception für Audit-Fehler."""


class AuditWriteError(AuditError):
    """Wird geworfen, wenn ein Audit-Eintrag nicht geschrieben werden kann."""


class AuditDirInconsistentError(AuditError):
    """Wird geworfen, wenn audit-logs/ inkonsistent ist (Owner, Modus)."""


def _hash_args(args: dict[str, Any] | None) -> str:
    """
    Erzeugt einen SHA-256-Hash der Argumente.

    Sensible Werte werden nicht im Klartext geloggt, sondern gehasht.
    """
    if not args:
        return "sha256:empty"
    canonical = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def new_audit_id() -> str:
    """Erzeugt eine Audit-ID im Format AUD-YYYY-MM-DD-XXXXXXXX."""
    now = datetime.now(UTC)
    suffix = uuid.uuid4().hex[:8]
    return f"AUD-{now.strftime('%Y-%m-%d')}-{suffix}"


@dataclass(frozen=True)
class AuditEntry:
    """
    Ein Audit-Eintrag.

    Unveränderlich. Jeder Eintrag wird genau einmal geschrieben.
    """
    agent: str
    tool: str
    policy_result: str
    permission_level: int
    execution_status: str
    audit_id: str = field(default_factory=new_audit_id)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    args_hash: str = "sha256:empty"
    duration_ms: int = 0
    output_hash: str = "sha256:empty"
    network_id: str = "homelab-default"
    details: dict[str, Any] | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        if self.policy_result not in VALID_POLICY_RESULTS:
            raise AuditError(
                f"Ungültiges policy_result: {self.policy_result}. "
                f"Erlaubt: {sorted(VALID_POLICY_RESULTS)}"
            )
        if self.permission_level < 0 or self.permission_level > 5:
            raise AuditError(
                f"permission_level muss zwischen 0 und 5 liegen: "
                f"{self.permission_level}"
            )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

    def to_json_line(self) -> str:
        """Serialisiert als JSON-Zeile (ohne Newline am Ende)."""
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


def check_audit_logs(
    base_dir: Path | str,
    expected_owner: str,
) -> None:
    """
    Prueft audit-logs/ auf Konsistenz (Owner, Modus).

    Wirft AuditDirInconsistentError bei jeder Abweichung.
    Ignoriert Nicht-*.jsonl-Dateien (z.B. README.md).
    """
    d = Path(base_dir)
    if not d.exists():
        raise AuditDirInconsistentError(
            f"Audit-Verzeichnis fehlt: {d}"
        )
    for f in sorted(d.glob("*.jsonl")):
        st = f.stat()
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            raise AuditDirInconsistentError(
                f"Unbekannter UID {st.st_uid} fuer Datei "
                f"{f.name}. Erwartet: {expected_owner}."
            )
        if owner != expected_owner:
            raise AuditDirInconsistentError(
                f"Owner {owner} (UID {st.st_uid}) fuer Datei "
                f"{f.name}. Erwartet: {expected_owner}."
            )
        mode = st.st_mode & 0o777
        if mode != 0o640:
            raise AuditDirInconsistentError(
                f"Modus {oct(mode)} fuer Datei {f.name}. "
                f"Erwartet: 0o640."
            )


class AuditWriter:
    """
    Schreibt Audit-Einträge als JSONL in Tagesdateien.

    Thread-safe. Append-only. Fail closed.
    """

    def __init__(self, base_dir: str | os.PathLike[str] = "audit-logs") -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _file_for(self, when: datetime) -> Path:
        """Gibt den Pfad der Tagesdatei zurück."""
        name = when.strftime("%Y-%m-%d") + ".jsonl"
        return self.base_dir / name


    def write(self, entry: AuditEntry) -> None:
        """
        Schreibt einen Audit-Eintrag.

        Regeln:
        - Append-only: öffnet die Datei mit "a".
        - fsync nach jedem Schreiben (Sicherheit vor Absturz).
        - Bei Fehler: AuditWriteError werfen (Fail closed).
        """
        path = self._file_for(entry.timestamp)
        line = entry.to_json_line() + "\n"

        with self._lock:
            try:
                # Auflage 471: fail closed bei falschem Modus
                # einer bereits existierenden Datei. Kein
                # Silent Repair. Neue Dateien werden mit
                # mode=0o640 angelegt (kein Check vorher).
                try:
                    if path.exists():
                        mode = os.stat(path).st_mode & 0o777
                        if mode != 0o640:
                            raise AuditWriteError(
                                f"Modus {oct(mode)} fuer "
                                f"{path.name}. Erwartet: 0o640."
                            )
                except FileNotFoundError as exc:
                    # Race zwischen exists() und stat():
                    # Datei wurde geloescht. Fail closed.
                    raise AuditWriteError(
                        f"Datei {path.name} verschwand zwischen "
                        f"Pruefung und Schreiben: {exc}"
                    ) from exc

                fd = os.open(
                    path,
                    os.O_CREAT | os.O_APPEND | os.O_WRONLY,
                    mode=0o640,
                )
                try:
                    os.chmod(path, 0o640)
                    with os.fdopen(fd, "a", encoding="utf-8") as fh:
                        fh.write(line)
                        fh.flush()
                        os.fsync(fh.fileno())
                except Exception:
                    os.close(fd)
                    raise
            except OSError as exc:
                raise AuditWriteError(
                    f"Audit-Eintrag konnte nicht geschrieben werden: {exc}"
                ) from exc

    def log(
        self,
        *,
        agent: str,
        tool: str,
        policy_result: str,
        permission_level: int,
        execution_status: str,
        args: dict[str, Any] | None = None,
        duration_ms: int = 0,
        output_hash: str = "sha256:empty",
        network_id: str = "homelab-default",
        details: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> AuditEntry:
        """
        Bequemer Wrapper: erzeugt AuditEntry und schreibt ihn.
        """
        entry = AuditEntry(
            agent=agent,
            tool=tool,
            policy_result=policy_result,
            permission_level=permission_level,
            execution_status=execution_status,
            args_hash=_hash_args(args),
            duration_ms=duration_ms,
            output_hash=output_hash,
            network_id=network_id,
            details=details,
            error=error,
        )
        self.write(entry)
        return entry

    def read_day(self, when: datetime | None = None) -> list[AuditEntry]:
        """
        Liest alle Einträge eines Tages (nur für Tests / Auswertung).
        """
        when = when or datetime.now(UTC)
        path = self._file_for(when)
        if not path.exists():
            return []
        entries: list[AuditEntry] = []
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                d = json.loads(raw)
                d["timestamp"] = datetime.fromisoformat(d["timestamp"])
                entries.append(AuditEntry(**d))
        return entries


__all__ = [
    "AuditEntry",
    "AuditDirInconsistentError",
    "AuditError",
    "AuditWriteError",
    "AuditWriter",
    "check_audit_logs",
    "new_audit_id",
]
