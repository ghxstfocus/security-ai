"""Tests fuer SecurityAI(skip_migrations=True).

skip_migrations=True: apply_migrations wird nicht aufgerufen.
Default: apply_migrations laeuft (Bestandsverhalten).
"""
from __future__ import annotations

import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from apps.security_ai import orchestrator as orc


class SkipMigrationsTests(unittest.TestCase):
    def _common_kwargs(self, tmp_path: Path) -> dict:
        # Nur minimale Pfade, damit SecurityAI() ohne
        # externe YAML/Policy-Abhaengigkeiten nicht scheitert.
        # Wir nutzen die echten Defaults, weil die im Repo liegen.
        return {
            "db_path": tmp_path / "x.db",
            "migrations_dir": Path("data/migrations"),
        }

    def test_default_calls_apply_migrations(self) -> None:
        with TemporaryDirectory() as d, mock.patch.object(
            orc, "apply_migrations",
        ) as m:
            orc.SecurityAI(
                db_path=Path(d) / "x.db",
                migrations_dir=Path("data/migrations"),
            )
            self.assertTrue(m.called)
            self.assertEqual(m.call_count, 1)

    def test_skip_migrations_does_not_call(self) -> None:
        with TemporaryDirectory() as d, mock.patch.object(
            orc, "apply_migrations",
        ) as m:
            orc.SecurityAI(
                db_path=Path(d) / "x.db",
                migrations_dir=Path("data/migrations"),
                skip_migrations=True,
            )
            self.assertFalse(m.called)


if __name__ == "__main__":
    unittest.main()
