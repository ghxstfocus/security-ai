"""
Tests fuer scripts/init_db.py und den Auto-Bootstrap in
scripts/chat_cli.py.

Alle Tests nutzen tmp_path (kein Zugriff auf data/inventory.db).
Kein Netz, kein Ollama.
"""
from __future__ import annotations

import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.access.repository import (
    PrincipalRepository,
    RoleRepository,
)
from scripts.chat_cli import main as chat_cli_main
from scripts.init_db import init_db
from scripts.init_db import main as init_db_main

MIGRATIONS = "data/migrations"


class _FakeOllama:
    """Minimaler Ollama-Ersatz fuer chat_cli-Tests."""

    def __init__(self, *args, **kwargs):
        pass

    def generate(self, request):
        from harness.llm.models import LLMResponse

        return LLMResponse(text="Antwort.", model=request.model)


def _patch_chat_cli_ollama() -> None:
    import scripts.chat_cli as chat_cli
    chat_cli.OllamaClient = _FakeOllama


# ---------------------------------------------------------------------- #
# init_db
# ---------------------------------------------------------------------- #

class InitDbTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.db = self.tmp / "inv.db"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # ------------------------------------------------------------------ #
    # Hilfen
    # ------------------------------------------------------------------ #

    def _tables(self) -> list[str]:
        conn = sqlite3.connect(self.db)
        t = sorted(r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"
        ))
        conn.close()
        return t

    def _principals(self) -> list[tuple[str, str]]:
        conn = sqlite3.connect(self.db)
        rows = list(conn.execute(
            "SELECT p.name, r.name FROM principals p "
            "JOIN roles r ON r.id = p.role_id "
            "ORDER BY p.name"
        ))
        conn.close()
        return rows

    # ------------------------------------------------------------------ #
    # Tests
    # ------------------------------------------------------------------ #

    def test_legt_db_und_migrationen_an(self):
        rc = init_db(
            db_path=self.db,
            migrations_dir=MIGRATIONS,
            with_principal=False,
            verbose=False,
        )
        self.assertEqual(rc, 0)
        self.assertTrue(self.db.exists())
        tables = self._tables()
        for t in ("roles", "permissions", "role_permissions",
                  "principals", "approvals", "change_requests",
                  "devices", "device_history", "whitelisted_devices"):
            self.assertIn(t, tables, t)

    def test_legt_cli_admin_an(self):
        rc = init_db(
            db_path=self.db,
            migrations_dir=MIGRATIONS,
            with_principal=True,
            principal_name="cli-admin",
            role_name="admin",
            verbose=False,
        )
        self.assertEqual(rc, 0)
        self.assertIn(("cli-admin", "admin"), self._principals())

    def test_no_principal_legt_keinen_an(self):
        rc = init_db(
            db_path=self.db,
            migrations_dir=MIGRATIONS,
            with_principal=False,
            verbose=False,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(self._principals(), [])

    def test_anderer_principal_und_rolle(self):
        rc = init_db(
            db_path=self.db,
            migrations_dir=MIGRATIONS,
            with_principal=True,
            principal_name="alice",
            role_name="viewer",
            verbose=False,
        )
        self.assertEqual(rc, 0)
        self.assertIn(("alice", "viewer"), self._principals())

    def test_idempotent(self):
        for _ in range(2):
            rc = init_db(
                db_path=self.db,
                migrations_dir=MIGRATIONS,
                with_principal=True,
                principal_name="cli-admin",
                role_name="admin",
                verbose=False,
            )
            self.assertEqual(rc, 0)
        # genau ein cli-admin
        names = [n for n, _ in self._principals()]
        self.assertEqual(names.count("cli-admin"), 1)

    def test_unbekannte_rolle_fail_closed(self):
        rc = init_db(
            db_path=self.db,
            migrations_dir=MIGRATIONS,
            with_principal=True,
            principal_name="bob",
            role_name="gibtsnicht",
            verbose=False,
        )
        self.assertEqual(rc, 1)

    def test_fehlender_migrations_ordner(self):
        rc = init_db(
            db_path=self.db,
            migrations_dir=self.tmp / "gibtsnicht",
            with_principal=False,
            verbose=False,
        )
        self.assertEqual(rc, 1)

    def test_main_mit_args(self):
        rc = init_db_main([
            "--db", str(self.db),
            "--migrations", MIGRATIONS,
            "--principal", "op1",
            "--role", "operator",
        ])
        self.assertEqual(rc, 0)
        self.assertIn(("op1", "operator"), self._principals())


# ---------------------------------------------------------------------- #
# chat_cli Auto-Bootstrap
# ---------------------------------------------------------------------- #

class ChatCliBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        _patch_chat_cli_ollama()
        self._tmp = TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.db = self.tmp / "inv.db"
        self.audit = self.tmp / "audit"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _principals(self) -> list[tuple[str, str]]:
        conn = sqlite3.connect(self.db)
        rows = list(conn.execute(
            "SELECT p.name, r.name FROM principals p "
            "JOIN roles r ON r.id = p.role_id"
        ))
        conn.close()
        return rows

    def test_auto_bootstrap_legt_db_und_cli_admin_an(self):
        rc = chat_cli_main([
            "--principal", "cli-admin",
            "--question", "Frage?",
            "--db", str(self.db),
            "--migrations-dir", MIGRATIONS,
            "--audit-base-dir", str(self.audit),
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(self.db.exists())
        self.assertIn(("cli-admin", "admin"), self._principals())

    def test_auto_bootstrap_idempotent(self):
        for _ in range(2):
            rc = chat_cli_main([
                "--principal", "cli-admin",
                "--question", "Frage?",
                "--db", str(self.db),
                "--migrations-dir", MIGRATIONS,
                "--audit-base-dir", str(self.audit),
            ])
            self.assertEqual(rc, 0)
        self.assertEqual(len(self._principals()), 1)

    def test_no_bootstrap_fail_closed(self):
        rc = chat_cli_main([
            "--principal", "cli-admin",
            "--question", "Frage?",
            "--no-bootstrap",
            "--db", str(self.db),
            "--migrations-dir", MIGRATIONS,
            "--audit-base-dir", str(self.audit),
        ])
        self.assertEqual(rc, 1)
        self.assertFalse(self.db.exists())

    def test_no_bootstrap_mit_vorhandener_db_ok(self):
        # DB vorher anlegen
        init_db(
            db_path=self.db,
            migrations_dir=MIGRATIONS,
            with_principal=True,
            principal_name="cli-admin",
            role_name="admin",
            verbose=False,
        )
        rc = chat_cli_main([
            "--principal", "cli-admin",
            "--question", "Frage?",
            "--no-bootstrap",
            "--db", str(self.db),
            "--migrations-dir", MIGRATIONS,
            "--audit-base-dir", str(self.audit),
        ])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
