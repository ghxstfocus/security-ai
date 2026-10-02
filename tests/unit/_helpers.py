# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Test-Helper fuer Unit-Tests.

Kein pytest-Fixture-Modul. Reine Funktionen, die
in Tests und Fixtures direkt aufgerufen werden
koennen.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask

from apps.dashboard.app import create_app
from apps.dashboard.decorators import SESSION_COOKIE_NAME
from core.access.models import PrincipalKind
from core.access.repository import (
    PrincipalRepository,
    RoleRepository,
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

    check_schema=False: Tests bauen eine
    frisch-migrierte DB selbst auf. Der
    Schema-Check wird separat in
    test_dashboard_app.py geprueft.

    check_audit=False: Tests laufen oft als root
    (kein Service-User security-ai). Der
    audit-logs-Check wird separat in
    test_audit_writer_rechte.py geprueft.
    """
    db = tmp_path / "t.db"
    app = create_app(
        check_audit=False,
        check_schema=False,
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


def migrated_conn(tmp_path: Path) -> sqlite3.Connection:
    """Frische migrierte SQLite-Verbindung.

    Helper, keine Fixture. tmp_path wird
    durchgereicht. Caller ist verantwortlich
    fuer close().
    """
    db_path = tmp_path / "test.db"
    c = connect(db_path)
    apply_migrations(c, DEFAULT_MIGRATIONS_DIR)
    return c


def create_role_client(app, role_name, tmp_name=None):
    """
    Erstellt Principal + Session + Test-Client
    fuer eine gegebene Rolle.

    tmp_name: optionaler Principal-Name. Default
    test-<role_name>. sid = sid-<name>.
    """
    name = tmp_name or f"test-{role_name}"
    sid = f"sid-{name}"
    conn = connect(app.config["DB_PATH"])
    role = RoleRepository(conn).get_by_name(role_name)
    PrincipalRepository(conn).create(
        name=name, role_id=role.row_id,
        kind=PrincipalKind.HUMAN,
    )
    SessionRepository(conn).create(sid, name)
    conn.close()
    c = app.test_client()
    set_session_cookie(c, sid)
    return c


__all__ = [
    "build_dashboard_app",
    "create_role_client",
    "migrated_conn",
    "set_session_cookie",
]
