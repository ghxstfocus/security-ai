"""
Konsistenz-Test: zu jedem KNOWN_SANDBOX_PROFILE muss eine
YAML-Datei in harness/sandbox/profiles/ existieren.

Verhindert stille Inkonsistenz zwischen tool.py und den
tatsaechlich vorhandenen Profil-Dateien.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from harness.tool_registry.tool import KNOWN_SANDBOX_PROFILES


PROFILES_DIR = Path("harness/sandbox/profiles")


class SandboxProfileFilesTests(unittest.TestCase):
    def test_profiles_dir_existiert(self):
        self.assertTrue(PROFILES_DIR.is_dir(),
                        f"{PROFILES_DIR} fehlt")

    def test_alle_known_profiles_haben_datei(self):
        missing = [
            name for name in sorted(KNOWN_SANDBOX_PROFILES)
            if not (PROFILES_DIR / f"{name}.yaml").is_file()
        ]
        self.assertEqual(
            missing, [],
            f"Fehlende Profil-Dateien in {PROFILES_DIR}: {missing}",
        )

    def test_keine_unbekannten_yaml_dateien(self):
        files = sorted(p.stem for p in PROFILES_DIR.glob("*.yaml"))
        unknown = [n for n in files if n not in KNOWN_SANDBOX_PROFILES]
        self.assertEqual(
            unknown, [],
            f"Unbekannte Profil-Dateien: {unknown}. "
            f"Entweder KNOWN_SANDBOX_PROFILES erweitern oder "
            f"Datei entfernen.",
        )

    def test_yaml_dateien_sind_parsebar(self):
        import yaml
        for p in sorted(PROFILES_DIR.glob("*.yaml")):
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
            self.assertIsInstance(data, dict, p.name)
            self.assertIn("name", data, p.name)
            self.assertEqual(data["name"], p.stem, p.name)


if __name__ == "__main__":
    unittest.main()
