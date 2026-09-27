"""
Tests fuer core/search/synonyms.py (Punkt 29, A786).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from core.search.synonyms import (
    SynonymError,
    expand_query,
    load_synonyms,
)
from core.services import ServiceError


def test_load_synonyms_liest_yaml():
    s = load_synonyms()
    assert "risk_category" in s
    assert "SECURITY_ALERT" in s["risk_category"]
    assert "alarm" in s["risk_category"]["SECURITY_ALERT"]


def test_expand_query_alarm():
    s = load_synonyms()
    assert expand_query("alarm", "risk_category", s) == [
        "alarm", "SECURITY_ALERT",
    ]


def test_expand_query_verdacht():
    s = load_synonyms()
    assert expand_query("verdacht", "risk_category", s) == [
        "verdacht", "SUSPICION",
    ]


def test_expand_query_freigegeben_in_approval_status():
    s = load_synonyms()
    assert expand_query("freigegeben", "approval_status", s) == [
        "freigegeben", "granted",
    ]


def test_expand_query_freigegeben_in_change_status():
    s = load_synonyms()
    assert expand_query("freigegeben", "change_status", s) == [
        "freigegeben", "approved",
    ]


def test_expand_query_unbekannt_gibt_original():
    s = load_synonyms()
    assert expand_query("xyz", "risk_category", s) == ["xyz"]


def test_expand_query_unbekanntes_feld_gibt_original():
    s = load_synonyms()
    assert expand_query("alarm", "unknown", s) == ["alarm"]


def test_expand_query_case_insensitive():
    s = load_synonyms()
    assert "SECURITY_ALERT" in expand_query(
        "ALARM", "risk_category", s,
    )


def test_synonym_error_is_service_error():
    assert issubclass(SynonymError, ServiceError)


def test_load_synonyms_fail_closed_fehlt(tmp_path):
    with pytest.raises(SynonymError):
        load_synonyms(tmp_path / "gibtsnicht.yaml")


def test_load_synonyms_fail_closed_kaputt(tmp_path):
    p = tmp_path / "bad.yaml"
    # Syntaktisch kaputtes YAML: ungleiche Klammer.
    p.write_text("a: [1, 2\n", encoding="utf-8")
    with pytest.raises(SynonymError):
        load_synonyms(p)


def test_load_synonyms_fail_closed_unbekannte_kategorie(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(
        "risk_category:\n"
        "  FOO:\n"
        "    - bar\n",
        encoding="utf-8",
    )
    with pytest.raises(SynonymError):
        load_synonyms(p)
