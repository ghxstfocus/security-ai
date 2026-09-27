"""
SearchService-Tests (3.6.16, Auflage 559).

Mock-Repo + Mock-Checker, Validierung, Permission-Filter,
risk_assessments-Python-Filter.
"""
from __future__ import annotations

import pytest

from core.services import ServiceError
from core.services.search_service import (
    QUERY_MAX, QUERY_MIN, SearchService, SearchServiceError,
)


class _FakeRepo:
    def __init__(self):
        self.calls = []

    def _hit(self, name, q, limit):
        self.calls.append((name, q, limit))
        return [{"identifier": q}] if q != "nix" else []

    def search_devices(self, q, limit):
        return self._hit("devices", q, limit)

    def search_whitelisted_devices(self, q, limit):
        return self._hit("whitelisted_devices", q, limit)

    def search_changes(self, q, limit):
        return self._hit("changes", q, limit)

    def search_approvals(self, q, limit):
        return self._hit("approvals", q, limit)

    def search_principals(self, q, limit):
        return self._hit("principals", q, limit)

    def search_roles(self, q, limit):
        return self._hit("roles", q, limit)

    def search_permissions(self, q, limit):
        return self._hit("permissions", q, limit)


class _FakeChecker:
    def __init__(self, perms):
        self.perms = frozenset(perms)

    def permissions_of(self, actor):
        return self.perms


def _svc(perms, ra=None):
    return SearchService(
        repo=_FakeRepo(),
        audit_reader=lambda **kw: ra or [],
        checker=_FakeChecker(perms),
    )


class TestValidation:
    def test_too_short(self):
        svc = _svc({"device.read"})
        with pytest.raises(SearchServiceError):
            svc.search("admin1", "a")

    def test_too_long(self):
        svc = _svc({"device.read"})
        with pytest.raises(SearchServiceError):
            svc.search("admin1", "x" * (QUERY_MAX + 1))

    def test_invalid_chars(self):
        svc = _svc({"device.read"})
        with pytest.raises(SearchServiceError):
            svc.search("admin1", "ab<script>")

    def test_non_string(self):
        svc = _svc({"device.read"})
        with pytest.raises(SearchServiceError):
            svc.search("admin1", None)

    def test_search_service_error_is_service_error(self):
        assert issubclass(SearchServiceError, ServiceError)


class TestPermissionFilter:
    def test_only_allowed_sources(self):
        svc = _svc({"device.read"})
        result = svc.search("admin1", "host")
        assert set(result.keys()) == {"devices", "whitelisted_devices"}

    def test_admin_sees_all(self):
        svc = _svc({
            "device.read", "change.view", "approval.view",
            "principal.manage", "role.manage", "audit.read",
        })
        result = svc.search("admin1", "host")
        assert "devices" in result
        assert "changes" in result
        assert "principals" in result

    def test_no_permission_no_sources(self):
        svc = _svc(set())
        assert svc.search("admin1", "host") == {}

    def test_empty_sources_removed(self):
        svc = _svc({"device.read"})
        # "nix" liefert leere Listen -> Quelle wird weggelassen.
        result = svc.search("admin1", "nix")
        assert result == {}


class TestRiskAssessments:
    def test_ra_filter_by_audit_id(self):
        ra = [
            {"audit_id": "AUD-2026-09-26-abcdef01", "event_id": "EVT-1",
             "rule_id": "port_scan", "tool": "risk_engine"},
            {"audit_id": "AUD-2026-09-26-ffffffff", "event_id": "EVT-2",
             "rule_id": "unknown_device", "tool": "risk_engine"},
        ]
        svc = _svc({"audit.read"}, ra=ra)
        result = svc.search("admin1", "abcdef")
        assert "risk_assessments" in result
        assert len(result["risk_assessments"]) == 1
        assert result["risk_assessments"][0]["audit_id"] == "AUD-2026-09-26-abcdef01"

    def test_ra_no_hit(self):
        ra = [{"audit_id": "AUD-2026-09-26-00000001",
               "event_id": None, "rule_id": None, "tool": None}]
        svc = _svc({"audit.read"}, ra=ra)
        assert "risk_assessments" not in svc.search("admin1", "xyz")

    def test_ra_filter_by_category(self):
        ra = [
            {"audit_id": "AUD-1", "event_id": "E1",
             "rule_id": "r1", "tool": "t1",
             "category": "CONFIRMED"},
            {"audit_id": "AUD-2", "event_id": "E2",
             "rule_id": "r2", "tool": "t2",
             "category": "SUSPICION"},
        ]
        svc = _svc({"audit.read"}, ra=ra)
        result = svc.search("admin1", "CONFIRMED")
        assert "risk_assessments" in result
        assert len(result["risk_assessments"]) == 1
        assert result["risk_assessments"][0]["category"] == "CONFIRMED"

    def test_ra_filter_by_category_lowercase(self):
        ra = [
            {"audit_id": "AUD-1", "event_id": "E1",
             "rule_id": "r1", "tool": "t1",
             "category": "SECURITY_ALERT"},
        ]
        svc = _svc({"audit.read"}, ra=ra)
        result = svc.search("admin1", "security_alert")
        assert "risk_assessments" in result
        assert len(result["risk_assessments"]) == 1


# --- Punkt 29: Synonym-Erweiterung (A786) --------------------------- #

class _SynRepo:
    """Repo, das die Dedup-Felder liefert (request_id, change_id)."""

    def __init__(self):
        self.approvals_calls = []
        self.changes_calls = []

    def search_approvals(self, q, limit):
        self.approvals_calls.append(q)
        # q="granted" oder q="freigegeben" -> ein Treffer
        if q in ("granted", "freigegeben"):
            return [{"request_id": "APR-2026-00001", "status": "granted"}]
        return []

    def search_changes(self, q, limit):
        self.changes_calls.append(q)
        if q in ("approved", "freigegeben"):
            return [{"change_id": "CHG-2026-00042", "status": "approved"}]
        return []


def test_synonym_alarm_findet_security_alert():
    ra = [
        {"audit_id": "A1", "event_id": "E1", "rule_id": "r",
         "tool": "risk_engine", "category": "SECURITY_ALERT"},
        {"audit_id": "A2", "event_id": "E2", "rule_id": "r",
         "tool": "risk_engine", "category": "SUSPICION"},
    ]
    svc = _svc({"audit.read"}, ra=ra)
    result = svc.search("admin1", "alarm")
    assert "risk_assessments" in result
    cats = [e["category"] for e in result["risk_assessments"]]
    assert "SECURITY_ALERT" in cats


def test_synonym_verdacht_findet_suspicion():
    ra = [
        {"audit_id": "A1", "event_id": "E1", "rule_id": "r",
         "tool": "risk_engine", "category": "SUSPICION"},
        {"audit_id": "A2", "event_id": "E2", "rule_id": "r",
         "tool": "risk_engine", "category": "CONFIRMED"},
    ]
    svc = _svc({"audit.read"}, ra=ra)
    result = svc.search("admin1", "verdacht")
    assert "risk_assessments" in result
    cats = [e["category"] for e in result["risk_assessments"]]
    assert cats == ["SUSPICION"]


def test_synonym_freigegeben_findet_approvals_und_changes():
    repo = _SynRepo()
    svc = SearchService(
        repo=repo,
        audit_reader=lambda **kw: [],
        checker=_FakeChecker({"approval.view", "change.view"}),
    )
    result = svc.search("admin1", "freigegeben")
    assert "approvals" in result
    assert result["approvals"][0]["status"] == "granted"
    assert "changes" in result
    assert result["changes"][0]["status"] == "approved"


def test_synonym_dedup_bei_doppeltem_treffer():
    repo = _SynRepo()
    svc = SearchService(
        repo=repo,
        audit_reader=lambda **kw: [],
        checker=_FakeChecker({"approval.view"}),
    )
    result = svc.search("admin1", "freigegeben")
    # Obwohl approvals zweimal gerufen wird (q + q_synonym),
    # nur ein Treffer in der Antwort (Dedup per request_id).
    assert len(result["approvals"]) == 1


def test_kein_synonym_bei_unbekanntem_begriff():
    repo = _SynRepo()
    svc = SearchService(
        repo=repo,
        audit_reader=lambda **kw: [],
        checker=_FakeChecker({"approval.view"}),
    )
    result = svc.search("admin1", "unbekannt")
    # Keine Treffer, aber keine Exception.
    assert "approvals" not in result
