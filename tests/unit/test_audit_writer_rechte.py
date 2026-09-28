"""Tests fuer Audit-Rechte (3.6.15b, Fix 13 + Fix 14).

Auflagen 462-473:
- 462: Fix 13 minimal (os.open, os.chmod).
- 467: kein expected_owner in AuditWriter.
- 468: Modus-Check nur bei existierender Datei.
- 471: fail closed bei falschem Modus, kein Silent Repair.
- 472: Test 2 prueft auch, dass die Datei NICHT
  korrigiert wird.
- 473: jeder Modus != 0o640 ist ein Fehler.
"""
from __future__ import annotations

import os
import stat
from datetime import UTC, datetime, timezone
from pathlib import Path

import pytest

from harness.audit.writer import (
    AuditDirInconsistentError,
    AuditEntry,
    AuditWriteError,
    AuditWriter,
    check_audit_logs,
)


def _entry() -> AuditEntry:
    return AuditEntry(
        agent="security_ai",
        tool="test",
        policy_result="ALLOWED",
        permission_level=0,
        execution_status="OK",
        timestamp=datetime.now(UTC),
    )


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# ------------------------------------------------------------------ #
# Fix 13 -- write() Modus-Check (Auflagen 468, 471, 472, 473)
# ------------------------------------------------------------------ #

def test_neue_datei_wird_640_angelegt(tmp_path):
        # Auflage 468: neue Datei, kein Check vorher.
        w = AuditWriter(base_dir=tmp_path)
        w.write(_entry())
        datei = tmp_path / (datetime.now(UTC)
                            .strftime("%Y-%m-%d") + ".jsonl")
        assert datei.exists()
        assert _mode(datei) == 0o640

def test_bestehende_datei_644_fail_closed(tmp_path):
        # Auflage 471/472: fail closed, kein Silent Repair.
        w = AuditWriter(base_dir=tmp_path)
        w.write(_entry())
        datei = tmp_path / (datetime.now(UTC)
                            .strftime("%Y-%m-%d") + ".jsonl")
        os.chmod(datei, 0o644)
        # Datei ist jetzt 644. Naechster Schreibversuch muss
        # fehlschlagen.
        with pytest.raises(AuditWriteError) as exc:
            w.write(_entry())
        assert "Modus" in str(exc.value)
        assert "0o640" in str(exc.value)
        # Auflage 472: Datei wurde NICHT korrigiert.
        assert _mode(datei) == 0o644

def test_bestehende_datei_600_fail_closed(tmp_path):
        # Auflage 473: jeder Modus != 0o640 ist ein Fehler.
        w = AuditWriter(base_dir=tmp_path)
        w.write(_entry())
        datei = tmp_path / (datetime.now(UTC)
                            .strftime("%Y-%m-%d") + ".jsonl")
        os.chmod(datei, 0o600)
        with pytest.raises(AuditWriteError):
            w.write(_entry())
        assert _mode(datei) == 0o600


# ------------------------------------------------------------------ #
# Fix 14 -- check_audit_logs (Auflagen 463, 464)
# ------------------------------------------------------------------ #

def test_leeres_verzeichnis_ok(tmp_path):
        check_audit_logs(tmp_path, expected_owner="irrelevant")
        # kein raise

def test_korrekte_datei_ok(tmp_path):
        w = AuditWriter(base_dir=tmp_path)
        w.write(_entry())
        import pwd as _pwd
        me = _pwd.getpwuid(os.getuid()).pw_name
        check_audit_logs(tmp_path, expected_owner=me)
        # kein raise

def test_falscher_owner_fail_closed(tmp_path, monkeypatch):
        w = AuditWriter(base_dir=tmp_path)
        w.write(_entry())
        # pwd.getpwuid so patchen, dass es einen fremden
        # Owner liefert.
        import harness.audit.writer as _writer_mod
        class _FakePw:
            pw_name = "fremder_user"
        monkeypatch.setattr(
            _writer_mod.pwd, "getpwuid",
            lambda uid: _FakePw(),
        )
        with pytest.raises(AuditDirInconsistentError) as exc:
            check_audit_logs(tmp_path, expected_owner="security-ai")
        assert "fremder_user" in str(exc.value)

def test_falscher_modus_fail_closed(tmp_path):
        w = AuditWriter(base_dir=tmp_path)
        w.write(_entry())
        datei = tmp_path / (datetime.now(UTC)
                            .strftime("%Y-%m-%d") + ".jsonl")
        os.chmod(datei, 0o644)
        import pwd as _pwd
        me = _pwd.getpwuid(os.getuid()).pw_name
        with pytest.raises(AuditDirInconsistentError) as exc:
            check_audit_logs(tmp_path, expected_owner=me)
        assert "Modus" in str(exc.value)

def test_readme_wird_ignoriert(tmp_path):
        # README.md ist keine *.jsonl-Datei.
        (tmp_path / "README.md").write_text(
            "x", encoding="utf-8",
        )
        # Wenn der Check nur *.jsonl prueft, gibt es keinen
        # Fehler, obwohl README.md den "falschen" Modus hat.
        import pwd as _pwd
        me = _pwd.getpwuid(os.getuid()).pw_name
        check_audit_logs(tmp_path, expected_owner=me)

def test_fehlendes_verzeichnis_fail_closed(tmp_path):
        with pytest.raises(AuditDirInconsistentError):
            check_audit_logs(
                tmp_path / "gibt_es_nicht",
                expected_owner="irrelevant",
            )
