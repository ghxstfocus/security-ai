"""
Punkt 16: gunicorn-Einstieg und ProxyFix (A647).

Kategorie 3, Auflage 647.

Prueft:
- ProxyFix ist in create_app() aktiv.
- wsgi.py enthaelt genau den erwarteten Inhalt
  (kein Import mit Seiteneffekt, kein Audit-Zugriff
  im Test).
"""
from __future__ import annotations

from pathlib import Path

from werkzeug.middleware.proxy_fix import ProxyFix


def test_proxyfix_is_active(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "x" * 48)
    from apps.dashboard.app import create_app
    app = create_app(
        check_audit=False,
        check_schema=False,
        db_path=tmp_path / "t.db",
        audit_base_dir=str(tmp_path / "audit"),
    )
    assert isinstance(app.wsgi_app, ProxyFix)


def test_wsgi_module_source():
    # Kein Import: der Import wuerde create_app() aufrufen
    # und in den fail-closed Audit-Check laufen. Wir pruefen
    # den Quelltext auf die erwartete Struktur.
    p = Path("apps/dashboard/wsgi.py")
    t = p.read_text(encoding="utf-8")
    assert "from apps.dashboard.app import create_app" in t
    assert "app = create_app()" in t
    # Kein Dev-Start-Block im WSGI-Modul.
    assert 'if __name__ ==' not in t
    assert ".run(" not in t
