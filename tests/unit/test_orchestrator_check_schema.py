# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer check_schema_version im SecurityAI.__init__.

Regression: STATUS.md Punkt 17 — check_schema_version fehlte beim
direkten SecurityAI()-Aufruf. tools/event_reader.py rief es
explizit auf, aber wer SecurityAI() direkt konstruierte, war
nicht fail-closed gegen veraltete DB-Schemas.

Diese Tests pruefen:
- Default (skip_migrations=False): check_schema_version wird
  nach apply_migrations aufgerufen.
- skip_migrations=True: check_schema_version wird NICHT aufgerufen
  (Aufrufer hat die Kontrolle, z.B. tools/event_reader.py).
"""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from apps.security_ai import orchestrator as orc


class CheckSchemaVersionTests(unittest.TestCase):
    def _common_kwargs(self, tmp_path: Path) -> dict:
        return {
            "db_path": tmp_path / "x.db",
            "migrations_dir": Path("data/migrations"),
        }

    def test_default_calls_check_schema_version(self) -> None:
        """skip_migrations=False (Default) -> check_schema_version laeuft."""
        with TemporaryDirectory() as d, \
             mock.patch.object(orc, "apply_migrations"), \
             mock.patch.object(orc, "check_schema_version") as m:
            orc.SecurityAI(
                db_path=Path(d) / "x.db",
                migrations_dir=Path("data/migrations"),
            )
            self.assertTrue(m.called)
            self.assertEqual(m.call_count, 1)

    def test_skip_migrations_does_not_call_check_schema_version(
            self) -> None:
        """skip_migrations=True -> check_schema_version NICHT aufgerufen."""
        with TemporaryDirectory() as d, \
             mock.patch.object(orc, "apply_migrations"), \
             mock.patch.object(orc, "check_schema_version") as m:
            orc.SecurityAI(
                db_path=Path(d) / "x.db",
                migrations_dir=Path("data/migrations"),
                skip_migrations=True,
            )
            self.assertFalse(m.called)

    def test_check_schema_version_receives_conn_and_migrations_dir(
            self) -> None:
        """check_schema_version bekommt (conn, migrations_dir)."""
        with TemporaryDirectory() as d, \
             mock.patch.object(orc, "apply_migrations"), \
             mock.patch.object(orc, "check_schema_version") as m:
            migrations_dir = Path("data/migrations")
            orc.SecurityAI(
                db_path=Path(d) / "x.db",
                migrations_dir=migrations_dir,
            )
            self.assertEqual(m.call_count, 1)
            args, _kwargs = m.call_args
            # args[0] ist die sqlite3.Connection, args[1] migrations_dir
            self.assertEqual(len(args), 2)
            self.assertEqual(args[1], migrations_dir)

    def test_schema_version_error_propagates(self) -> None:
        """SchemaVersionError wird nicht gefangen (fail-closed)."""
        from core.inventory.repository import SchemaVersionError
        with TemporaryDirectory() as d, \
             mock.patch.object(orc, "apply_migrations"), \
             mock.patch.object(
                 orc, "check_schema_version",
                 side_effect=SchemaVersionError("kaputt"),
             ):
            with self.assertRaises(SchemaVersionError):
                orc.SecurityAI(
                    db_path=Path(d) / "x.db",
                    migrations_dir=Path("data/migrations"),
                )


if __name__ == "__main__":
    unittest.main()
