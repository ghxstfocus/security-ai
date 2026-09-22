"""
Test-Helper fuer Unit-Tests.

Kein pytest-Fixture-Modul. Reine Funktionen, die
in Tests und Fixtures direkt aufgerufen werden
koennen.
"""
from __future__ import annotations

from pathlib import Path

from flask import Flask

from apps.dashboard.app import create_app
from apps.dashboard.decorators import SESSION_COOKIE_NAME
from core.access.models import PrincipalKind
from core.access.repository import (
    PrincipalRepository, RoleRepository,
)
from core.access.session_repo import SessionRepository
from core.inventory.repository import (
    DEFAULT_MIGRATIONS_DIR,
    apply_migrations,
    connect,
)


def set_session_cookie(client, value):
    """
    Setzt das Session-Cookie mit den Produktions-Flags.

    Helper, keine Fixture. Grund: Fixtures rufen ihn
    innerhalb anderer Fixtures auf (client,
    viewer_client).
    """
    client.set_cookie(
        SESSION_COOKIE_NAME, value,
        domain="localhost",
        secure=True, httponly=True, samesite="Strict",
    )
    return client



def build_dashboard_app(tmp_path: Path) -> Flask:
    """
    Baut die Dashboard-Test-App (tmp-DB + tmp-Audit).

    Enthaelt:
    - admin1 (Rolle admin)
    - viewer1 (Rolle viewer)
    - Sessions sid-1 (admin1), sid-viewer (viewer1)

    Dashboard-spezifisch. Nicht in conftest.py,
    damit andere Tests sie nicht versehentlich
    anfordern.
    """
    db = tmp_path / "t.db"
    app = create_app(
        db_path=db,
        migrations_dir=DEFAULT_MIGRATIONS_DIR,
        audit_base_dir=str(tmp_path / "audit"),
        secret_key="x" * 48,
    )
    conn = connect(db)
    apply_migrations(conn, DEFAULT_MIGRATIONS_DIR)
    roles = RoleRepository(conn)
    principals = PrincipalRepository(conn)
    admin_role = roles.get_by_name("admin")
    viewer_role = roles.get_by_name("viewer")
    principals.create(
        name="admin1", role_id=admin_role.row_id,
        kind=PrincipalKind.HUMAN,
    )
    principals.create(
        name="viewer1", role_id=viewer_role.row_id,
        kind=PrincipalKind.HUMAN,
    )
    sr = SessionRepository(conn)
    sr.create("sid-1", "admin1")
    sr.create("sid-viewer", "viewer1")
    conn.close()
    return app


__all__ = [
    "build_dashboard_app",
    "set_session_cookie",
]
