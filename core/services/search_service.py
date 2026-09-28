"""
SearchService: Globale Suche ueber alle Quellen.

Kategorie 3 (3.6.16, Auflagen 525-558).

Design:
- Validierung im Service (Auflage 538, 532).
- Permission pro Quelle (Auflage 525/526):
  Quellen ohne Permission werden entfernt.
- Reihenfolge der Quellen fest (Auflage 542).
- Limit pro Quelle: 20 (Auflage 531/552).
- Leere Quellen werden weggelassen (Auflage 534).
- risk_assessments: Python-Filter ueber die Liste aus
  read_risk_assessments (Auflage 557).
- Kein Audit: reiner Lesevorgang (analog AuditReaderService).

Reihenfolge (A542):
  devices, whitelisted_devices, changes, approvals,
  principals, roles, permissions, risk_assessments.

Permissions pro Quelle (A525):
  devices              -> device.read
  whitelisted_devices  -> device.read
  changes              -> change.view
  approvals            -> approval.view
  principals           -> principal.manage
  roles                -> role.manage
  permissions          -> role.manage
  risk_assessments     -> audit.read
"""
from __future__ import annotations

import re
from typing import Any, Callable

from core.access.checker import AccessChecker
from core.search.repository import DEFAULT_LIMIT, SearchRepository
from core.search.synonyms import expand_query, load_synonyms
from core.services import ServiceError

# Zeichen-Whitelist (Auflage 532).
QUERY_RE = re.compile(r"^[A-Za-z0-9 ._:/@-]+$")
QUERY_MIN = 2
QUERY_MAX = 200

# Feste Reihenfolge (Auflage 542).
SOURCE_ORDER = (
    "devices",
    "whitelisted_devices",
    "changes",
    "approvals",
    "principals",
    "roles",
    "permissions",
    "risk_assessments",
)

# Permission pro Quelle (Auflage 525).
SOURCE_PERMISSION = {
    "devices": "device.read",
    "whitelisted_devices": "device.read",
    "changes": "change.view",
    "approvals": "approval.view",
    "principals": "principal.manage",
    "roles": "role.manage",
    "permissions": "role.manage",
    "risk_assessments": "audit.read",
}

# Felder fuer den risk_assessments-Python-Filter (A557).
# Auflage 735 (3.6.18a): category ergaenzt.
# Der Filter laeuft in Python (risk_assessments
# kommen aus JSONL, kein SQL).
RA_FIELDS = ("audit_id", "event_id", "rule_id", "tool", "category")


class SearchServiceError(ServiceError):
    """Fachlicher Fehler im SearchService (4xx)."""


class SearchService:
    def __init__(
        self,
        repo: SearchRepository,
        audit_reader: Callable[..., list[dict[str, Any]]],
        checker: AccessChecker,
        *,
        synonyms: dict | None = None,
    ) -> None:
        if repo is None:
            raise SearchServiceError(
                "repo ist Pflicht (fail closed)"
            )
        if audit_reader is None:
            raise SearchServiceError(
                "audit_reader ist Pflicht (fail closed)"
            )
        if checker is None:
            raise SearchServiceError(
                "checker ist Pflicht (fail closed)"
            )
        self._repo = repo
        self._audit_reader = audit_reader
        self._checker = checker
        self._synonyms = (
            synonyms if synonyms is not None
            else load_synonyms()
        )

    # ------------------------------------------------------------------ #
    # Validierung (A532, A538)
    # ------------------------------------------------------------------ #
    def _validate(self, q: object) -> str:
        if not isinstance(q, str):
            raise SearchServiceError("q muss String sein")
        q = q.strip()
        if len(q) < QUERY_MIN:
            raise SearchServiceError("q zu kurz")
        if len(q) > QUERY_MAX:
            raise SearchServiceError("q zu lang")
        if not QUERY_RE.match(q):
            raise SearchServiceError("q enthaelt ungueltige Zeichen")
        return q

    # ------------------------------------------------------------------ #
    # Berechtigungen
    # ------------------------------------------------------------------ #
    def _allowed_sources(self, actor: str) -> set[str]:
        try:
            perms = self._checker.permissions_of(actor)
        except Exception:
            return set()
        return {
            src for src in SOURCE_ORDER
            if SOURCE_PERMISSION[src] in perms
        }

    # ------------------------------------------------------------------ #
    # risk_assessments (Python-Filter, A557)
    # ------------------------------------------------------------------ #
    def _filter_risk_assessments(
        self, q_values: list[str], limit: int,
    ) -> list[dict[str, Any]]:
        """
        q_values: Liste von Suchstrings (Original +
        Synonym-Zielwerte). Ein Treffer, wenn
        irgendein Wert in einem RA_FIELDS-Feld
        vorkommt (case-insensitiv).
        """
        try:
            entries = self._audit_reader(
                since_hours=24, max_entries=50,
            )
        except Exception:
            return []
        lowers = [v.lower() for v in q_values if isinstance(v, str)]
        out: list[dict[str, Any]] = []
        for e in entries:
            if not isinstance(e, dict):
                continue
            for f in RA_FIELDS:
                v = e.get(f)
                if not isinstance(v, str):
                    continue
                vl = v.lower()
                if any(ql in vl for ql in lowers):
                    out.append(e)
                    break
            if len(out) >= limit:
                break
        return out

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def search(
        self, actor: str, q: str, limit: int = DEFAULT_LIMIT,
    ) -> dict[str, list[dict[str, Any]]]:
        q_ok = self._validate(q)
        allowed = self._allowed_sources(actor)
        result: dict[str, list[dict[str, Any]]] = {}

        # Auflage 781: Synonym-Feld pro Quelle.
        syn_fields = {
            "risk_assessments": "risk_category",
            "approvals": "approval_status",
            "changes": "change_status",
        }
        # Dedup-Key pro Quelle (Auflage 780).
        dedup_keys = {
            "risk_assessments": "audit_id",
            "approvals": "request_id",
            "changes": "change_id",
        }

        for src in SOURCE_ORDER:
            if src not in allowed:
                continue
            syn_field = syn_fields.get(src)
            if syn_field:
                q_values = expand_query(
                    q_ok, syn_field, self._synonyms,
                )
            else:
                q_values = [q_ok]

            if src == "risk_assessments":
                hits = self._filter_risk_assessments(
                    q_values, limit,
                )
            else:
                method = getattr(self._repo, f"search_{src}")
                hits = self._search_with_synonyms(
                    method, q_values, limit,
                )

            if hits:
                dk = dedup_keys.get(src)
                if dk:
                    seen: set = set()
                    deduped: list[dict[str, Any]] = []
                    for h in hits:
                        k = h.get(dk) if isinstance(h, dict) else None
                        if k is not None:
                            if k in seen:
                                continue
                            seen.add(k)
                        deduped.append(h)
                    hits = deduped
                result[src] = hits[:limit]
        return result

    def _search_with_synonyms(
        self, method, q_values: list[str], limit: int,
    ) -> list[dict[str, Any]]:
        """
        Ruft die Repo-Methode fuer jeden q-Wert auf und
        merged die Ergebnisse. Bei nur einem Wert:
        ein Aufruf.
        """
        if len(q_values) == 1:
            return method(q_values[0], limit)
        alle: list[dict[str, Any]] = []
        for v in q_values:
            alle.extend(method(v, limit))
        return alle


__all__ = [
    "SearchService",
    "SearchServiceError",
    "SOURCE_ORDER",
    "SOURCE_PERMISSION",
    "QUERY_MAX",
    "QUERY_MIN",
    "QUERY_RE",
]
