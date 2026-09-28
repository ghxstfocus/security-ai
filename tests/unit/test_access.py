"""
Tests fuer core/access/checker.py (AccessChecker).

DI-Variante mit Repos + from_conn.
"""
from __future__ import annotations

import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.access.checker import AccessChecker, AccessDeniedError
from core.access.models import PrincipalKind
from core.access.repository import (
    PermissionRepository,
    PrincipalRepository,
    RoleRepository,
)
from core.inventory.repository import apply_migrations


class AccessCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.conn = sqlite3.connect(self.tmp / "inv.db")
        apply_migrations(self.conn, "data/migrations")

        self.principals = PrincipalRepository(self.conn)
        self.roles = RoleRepository(self.conn)
        self.perms = PermissionRepository(self.conn)

        admin = self.roles.get_by_name("admin")
        viewer = self.roles.get_by_name("viewer")
        self.principals.create(
            name="admin", role_id=admin.row_id,
            kind=PrincipalKind.HUMAN,
        )
        self.principals.create(
            name="viewer1", role_id=viewer.row_id,
            kind=PrincipalKind.HUMAN,
        )
        self.principals.create(
            name="inactive", role_id=viewer.row_id,
            kind=PrincipalKind.HUMAN,
        )
        self.principals.set_active("inactive", False)

        self.checker = AccessChecker(
            self.principals, self.roles, self.perms,
        )

    def tearDown(self) -> None:
        self.conn.close()
        self._tmp.cleanup()

    # ------------------------------------------------------------------ #
    # check
    # ------------------------------------------------------------------ #

    def test_check_ok(self):
        self.assertTrue(self.checker.check("admin", "chat.ask"))
        self.assertTrue(self.checker.check("admin", "principal.manage"))

    def test_check_fehlt(self):
        self.assertFalse(self.checker.check("viewer1", "approval.decide"))

    def test_check_unbekannter_principal(self):
        self.assertFalse(self.checker.check("gibtsnicht", "chat.ask"))

    def test_check_unbekannte_permission(self):
        self.assertFalse(self.checker.check("admin", "gibtsnicht"))

    def test_check_inaktiv(self):
        self.assertFalse(self.checker.check("inactive", "chat.ask"))

    def test_check_leere_werte(self):
        self.assertFalse(self.checker.check("", "chat.ask"))
        self.assertFalse(self.checker.check("admin", ""))
        self.assertFalse(self.checker.check(None, "chat.ask"))
        self.assertFalse(self.checker.check("admin", None))

    # ------------------------------------------------------------------ #
    # has_permission (Alias)
    # ------------------------------------------------------------------ #

    def test_has_permission_alias(self):
        self.assertTrue(self.checker.has_permission("admin", "chat.ask"))
        self.assertFalse(
            self.checker.has_permission("viewer1", "approval.decide")
        )

    # ------------------------------------------------------------------ #
    # require_permission
    # ------------------------------------------------------------------ #

    def test_require_permission_ok(self):
        # kein raise
        self.checker.require_permission("admin", "chat.ask")

    def test_require_permission_wirft(self):
        with self.assertRaises(AccessDeniedError):
            self.checker.require_permission("viewer1", "approval.decide")

    def test_require_permission_unbekannt(self):
        with self.assertRaises(AccessDeniedError):
            self.checker.require_permission("gibtsnicht", "chat.ask")

    # ------------------------------------------------------------------ #
    # role_of
    # ------------------------------------------------------------------ #

    def test_role_of_ok(self):
        self.assertEqual(self.checker.role_of("admin"), "admin")
        self.assertEqual(self.checker.role_of("viewer1"), "viewer")

    def test_role_of_unbekannt(self):
        self.assertIsNone(self.checker.role_of("gibtsnicht"))

    def test_role_of_inaktiv(self):
        self.assertIsNone(self.checker.role_of("inactive"))

    def test_role_of_leer(self):
        self.assertIsNone(self.checker.role_of(""))
        self.assertIsNone(self.checker.role_of(None))

    # ------------------------------------------------------------------ #
    # permissions_of
    # ------------------------------------------------------------------ #

    def test_permissions_of_admin(self):
        perms = self.checker.permissions_of("admin")
        self.assertIn("chat.ask", perms)
        self.assertIn("principal.manage", perms)

    def test_permissions_of_viewer(self):
        perms = self.checker.permissions_of("viewer1")
        self.assertEqual(
            perms, frozenset({"chat.ask", "device.read", "audit.read"})
        )

    def test_permissions_of_unbekannt(self):
        self.assertEqual(
            self.checker.permissions_of("gibtsnicht"), frozenset()
        )

    def test_permissions_of_inaktiv(self):
        self.assertEqual(
            self.checker.permissions_of("inactive"), frozenset()
        )

    # ------------------------------------------------------------------ #
    # from_conn
    # ------------------------------------------------------------------ #

    def test_from_conn(self):
        c = AccessChecker.from_conn(self.conn)
        self.assertTrue(c.check("admin", "chat.ask"))
        self.assertFalse(c.check("viewer1", "approval.decide"))
        self.assertEqual(c.role_of("admin"), "admin")


if __name__ == "__main__":
    unittest.main()
