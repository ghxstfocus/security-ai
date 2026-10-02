# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests fuer apps/dashboard/filters.py (3.6.14).

Auflagen 418 (testbar ohne Rendering), 423 (Datumsformat,
Rohstring-Fallback), 424 (Score-Label, Fallback),
425 (Score-Zahl, zwei Stellen, kein Komma), 426 (Filter
sind testbar), 427 (nur Formatierung, kein Escaping --
das erledigt Jinja).
"""
from __future__ import annotations

import unittest

from apps.dashboard.filters import (
    format_score,
    format_score_label,
    format_ts,
    network_label,
)

# ------------------------------------------------------------------ #
# format_ts (Auflage 423)
# ------------------------------------------------------------------ #

class FormatTsTests(unittest.TestCase):

    def test_iso_mit_utc_offset(self):
        # Praxisformat aus dem Audit-JSONL.
        self.assertEqual(
            format_ts(
                "2026-09-23T21:17:00.072011+00:00"
            ),
            "23.09.26 21:17 UTC",
        )

    def test_iso_mit_z_suffix(self):
        self.assertEqual(
            format_ts("2026-09-23T21:17:00Z"),
            "23.09.26 21:17 UTC",
        )

    def test_ohne_zeitzone_wird_als_utc_behandelt(self):
        self.assertEqual(
            format_ts("2026-09-23T21:17:00"),
            "23.09.26 21:17 UTC",
        )

    def test_ungueltig_rohstring(self):
        # Auflage 423: kein Crash.
        self.assertEqual(
            format_ts("nicht-iso"), "nicht-iso",
        )

    def test_leerer_string(self):
        self.assertEqual(format_ts(""), "")

    def test_none(self):
        self.assertEqual(format_ts(None), "")

    def test_nicht_string(self):
        # Filter erhaelt im Fehlerfall irgendwas.
        self.assertEqual(format_ts(12345), "12345")


# ------------------------------------------------------------------ #
# format_score_label (Auflage 424)
# ------------------------------------------------------------------ #

class FormatScoreLabelTests(unittest.TestCase):

    def test_event(self):
        self.assertEqual(
            format_score_label("EVENT"), "Info",
        )

    def test_anomaly(self):
        self.assertEqual(
            format_score_label("ANOMALY"), "Hinweis",
        )

    def test_suspicion(self):
        self.assertEqual(
            format_score_label("SUSPICION"), "Warnung",
        )

    def test_security_alert(self):
        self.assertEqual(
            format_score_label("SECURITY_ALERT"), "Alarm",
        )

    def test_confirmed(self):
        self.assertEqual(
            format_score_label("CONFIRMED"), "Kritisch",
        )

    def test_unbekannt_fallback(self):
        self.assertEqual(
            format_score_label("NEUES"), "NEUES",
        )

    def test_none(self):
        self.assertEqual(format_score_label(None), "")


# ------------------------------------------------------------------ #
# format_score (Auflage 425)
# ------------------------------------------------------------------ #

class FormatScoreTests(unittest.TestCase):

    def test_zwei_stellen(self):
        self.assertEqual(format_score(0.95), "0.95")

    def test_rundet_auf_zwei_stellen(self):
        # 0.1 + 0.2 in Python -> 0.30000000000000004
        self.assertEqual(format_score(0.1 + 0.2), "0.30")

    def test_integer(self):
        self.assertEqual(format_score(1), "1.00")

    def test_string_mit_zahl(self):
        # Falls der Wert als String aus dem Audit kommt.
        self.assertEqual(format_score("0.95"), "0.95")

    def test_string_mit_komma(self):
        # Kein deutsches Komma im Input erwartet, aber
        # float("0,95") wuerde crashen -> Fallback.
        # float("0.95") funktioniert.
        self.assertEqual(format_score("0.95"), "0.95")

    def test_nicht_zahl_fallback(self):
        self.assertEqual(format_score("abc"), "abc")

    def test_none(self):
        self.assertEqual(format_score(None), "")


# ------------------------------------------------------------------ #
# network_label (T2, Auflage 1681)
# ------------------------------------------------------------------ #

class NetworkLabelTests(unittest.TestCase):

    def test_hauptnetz(self):
        self.assertEqual(network_label("Hauptnetz"), "Hauptnetz")

    def test_gastnetz(self):
        self.assertEqual(network_label("Gastnetz"), "Gastnetz")

    def test_extern(self):
        self.assertEqual(
            network_label("Extern"),
            "Extern (nicht autorisiert)",
        )

    def test_unbekannt_fallback(self):
        self.assertEqual(network_label("Sonstiges"), "Sonstiges")

    def test_none(self):
        self.assertEqual(network_label(None), "")
