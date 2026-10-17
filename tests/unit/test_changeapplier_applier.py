"""Tests fuer den ChangeApplier (apply + backup)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from core.changeapplier.applier import ChangeApplier
from core.changeapplier.models import Change, ChangeState


class ChangeApplierApplyTests(unittest.TestCase):
    """Gate-Tests fuer apply + backup."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.config_path = self.base / "config.yaml"
        self.backup_dir = self.base / "backups"
        self.config_path.write_text(
            yaml.safe_dump(
                {
                    "server": {
                        "host": "127.0.0.1",
                        "port": 80,
                        "tls": {"enabled": False, "ciphers": ["a", "b"]},
                    },
                    "logging": {"level": "info"},
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )

    def _make_change(self, payload: dict) -> Change:
        return Change(
            id="chg-1",
            target=str(self.config_path),
            payload=payload,
        )

    def _read_config(self) -> dict:
        with self.config_path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)

    def test_apply_merged_verschachteltes_dict(self) -> None:
        applier = ChangeApplier(self.config_path, self.backup_dir)
        change = self._make_change(
            {"server": {"tls": {"enabled": True}}}
        )

        applier.apply(change)

        data = self._read_config()
        self.assertTrue(data["server"]["tls"]["enabled"])
        # Nicht ueberschriebene Geschwister bleiben erhalten.
        self.assertEqual(data["server"]["tls"]["ciphers"], ["a", "b"])
        self.assertEqual(data["server"]["host"], "127.0.0.1")
        self.assertEqual(data["server"]["port"], 80)

    def test_apply_merged_liste_wird_ersetzt(self) -> None:
        applier = ChangeApplier(self.config_path, self.backup_dir)
        change = self._make_change(
            {"server": {"tls": {"ciphers": ["x"]}}}
        )

        applier.apply(change)

        data = self._read_config()
        self.assertEqual(data["server"]["tls"]["ciphers"], ["x"])

    def test_apply_merged_skalar_ueberschreibt(self) -> None:
        applier = ChangeApplier(self.config_path, self.backup_dir)
        change = self._make_change({"server": {"port": 8080}})

        applier.apply(change)

        data = self._read_config()
        self.assertEqual(data["server"]["port"], 8080)

    def test_apply_erstellt_backup(self) -> None:
        applier = ChangeApplier(self.config_path, self.backup_dir)
        change = self._make_change({"server": {"port": 8080}})

        applier.apply(change)

        backup_path = self.backup_dir / f"{change.id}.bak"
        self.assertTrue(backup_path.exists())
        with backup_path.open("r", encoding="utf-8") as handle:
            backup_data = yaml.safe_load(handle)
        self.assertEqual(backup_data["server"]["port"], 80)

    def test_apply_target_mismatch_setzt_failed(self) -> None:
        applier = ChangeApplier(self.config_path, self.backup_dir)
        change = Change(
            id="chg-2",
            target=str(self.base / "andere.yaml"),
            payload={"server": {"port": 8080}},
        )

        with self.assertRaises(ValueError):
            applier.apply(change)

        self.assertEqual(change.state, ChangeState.FAILED)

    def test_apply_fehler_setzt_failed_und_propagiert(self) -> None:
        # Kaputte Zieldatei: yaml.safe_load wirft einen
        # yaml.YAMLError. apply() wrappt das in ValueError
        # (U2a3: einheitliche Exception-Klasse fuer
        # ungueltige Eingaben).
        self.config_path.write_text(
            "server: [unbalanced\n", encoding="utf-8"
        )
        applier = ChangeApplier(self.config_path, self.backup_dir)
        change = self._make_change({"server": {"port": 8080}})

        with self.assertRaises(ValueError):
            applier.apply(change)

        self.assertEqual(change.state, ChangeState.FAILED)


class ChangeApplierRollbackTests(unittest.TestCase):
    """Gate-Tests fuer rollback (idempotent)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.config_path = self.base / "config.yaml"
        self.backup_dir = self.base / "backups"
        self.config_path.write_text(
            yaml.safe_dump(
                {
                    "server": {
                        "host": "127.0.0.1",
                        "port": 80,
                        "tls": {"enabled": False, "ciphers": ["a", "b"]},
                    },
                    "logging": {"level": "info"},
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )

    def _make_change(self, payload: dict) -> Change:
        return Change(
            id="chg-1",
            target=str(self.config_path),
            payload=payload,
        )

    def _read_config(self) -> dict:
        with self.config_path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)

    def test_rollback_stellt_original_her(self) -> None:
        applier = ChangeApplier(self.config_path, self.backup_dir)
        change = self._make_change({"server": {"port": 8080}})

        applier.apply(change)
        self.assertEqual(self._read_config()["server"]["port"], 8080)

        applier.rollback(change)

        data = self._read_config()
        self.assertEqual(data["server"]["port"], 80)
        self.assertEqual(data["server"]["host"], "127.0.0.1")
        self.assertEqual(data["server"]["tls"]["ciphers"], ["a", "b"])
        self.assertEqual(data["logging"]["level"], "info")

    def test_rollback_zweites_mal_ist_noop(self) -> None:
        applier = ChangeApplier(self.config_path, self.backup_dir)
        change = self._make_change({"server": {"port": 8080}})

        applier.apply(change)
        applier.rollback(change)
        # Zweiter rollback darf keinen Fehler werfen und das
        # Original nicht veraendern.
        applier.rollback(change)

        data = self._read_config()
        self.assertEqual(data["server"]["port"], 80)
        self.assertEqual(data["server"]["host"], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()