"""
Tests fuer core/context/links.py (Punkt 30, Auflage 771).
"""
from __future__ import annotations

from core.context.links import _is_allowed_href, extract_links


class _Checker:
    def __init__(self, perms):
        self._perms = frozenset(perms)

    def check(self, principal, code):
        return code in self._perms


def _checker(**kwargs):
    erlaubt = [code for code, ok in kwargs.items() if ok]
    return _Checker(erlaubt)


def test_change_id_mit_permission():
    c = _checker(**{"change.view": True})
    links = extract_links(
        "Aenderung CHG-2026-00042 ist offen.", "admin1", c,
    )
    assert len(links) == 1
    assert links[0]["label"] == "CHG-2026-00042"
    assert links[0]["href"] == "/changes/CHG-2026-00042"


def test_change_id_ohne_permission():
    c = _checker(**{"change.view": False})
    links = extract_links(
        "Aenderung CHG-2026-00042 ist offen.", "viewer1", c,
    )
    assert links == []


def test_audit_id():
    c = _checker(**{"audit.read": True})
    links = extract_links(
        "Eintrag AUD-2026-09-27-abcdef01.", "admin1", c,
    )
    assert len(links) == 1
    assert links[0]["href"] == "/audit/AUD-2026-09-27-abcdef01"


def test_approval_id():
    c = _checker(**{"approval.view": True})
    links = extract_links(
        "Antrag APR-2026-00001 offen.", "admin1", c,
    )
    assert len(links) == 1
    assert links[0]["href"] == "/approvals/APR-2026-00001"


def test_ip_mit_device_read():
    c = _checker(**{"device.read": True})
    links = extract_links(
        "Geraet 192.168.178.50 gesehen.", "admin1", c,
    )
    assert len(links) == 1
    assert links[0]["href"] == "/inventory/192.168.178.50"


def test_doppelte_id_nur_einmal():
    c = _checker(**{"change.view": True})
    links = extract_links(
        "CHG-2026-00042 und nochmal CHG-2026-00042.",
        "admin1", c,
    )
    assert len(links) == 1


def test_javascript_url_wird_nicht_erkannt():
    c = _checker(**{"change.view": True})
    links = extract_links(
        "javascript:alert(1)", "admin1", c,
    )
    assert links == []


def test_http_url_wird_nicht_erkannt():
    c = _checker(**{"change.view": True})
    links = extract_links(
        "http://evil.example.com", "admin1", c,
    )
    assert links == []


def test_leerer_text():
    c = _checker(**{"change.view": True})
    assert extract_links("", "admin1", c) == []
    assert extract_links(None, "admin1", c) == []


def test_reihenfolge_nach_vorkommen():
    c = _checker(**{"change.view": True, "audit.read": True})
    links = extract_links(
        "Erst CHG-2026-00042, dann AUD-2026-09-27-abcdef01.",
        "admin1", c,
    )
    assert [l["label"] for l in links] == [
        "CHG-2026-00042",
        "AUD-2026-09-27-abcdef01",
    ]


# --- A880: /alerts exakt, kein /alerts/<id> ------------------------ #

def test_allowed_href_alerts_exact():
    assert _is_allowed_href("/alerts") is True


def test_allowed_href_alerts_mit_suffix_verboten():
    assert _is_allowed_href("/alerts/foo") is False


def test_allowed_href_audit_prefix_erlaubt():
    assert _is_allowed_href("/audit/AUD-2026-01-01-abcdef01") is True


def test_allowed_href_extern_verboten():
    assert _is_allowed_href("https://evil.example/") is False
    assert _is_allowed_href("//evil.example/") is False
