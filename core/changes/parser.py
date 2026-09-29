"""
Parser: JSON <-> ChangeRequest.

Verantwortung:
- Dikt -> ChangeRequest (validate + build), fail closed.
- ChangeRequest -> Dikt (fuer Export in changes/CHG-YYYY-NNNNN.json).
- Datei lesen/schreiben (Pfad-Konvention changes/<change_id>.json).

Kein jsonschema. Handgeschriebene Validierung: Pflichtfelder,
Typen, Enum-Werte. Fail closed bei jeder Unstimmigkeit.

JSON-Format (siehe auch docs/DESIGN_DECISIONS.md):
  Pflicht: change_id, timestamp, title, description,
           requested_by, status, type.
  Optional: diff_or_patch, files_affected, rollback_plan,
            test_plan, related_approval_id, related_event_id,
            risk_category, risk_score, decided_at, decided_by,
            decision_reason, deployed_at, rolled_back_at.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from core.changes.models import (
    ChangeRequest,
    ChangeStatus,
    ChangeType,
    require_utc_iso,
    utc_now_iso,
)

DEFAULT_CHANGES_DIR = "changes"

_PFLICHT_FELDER = (
    "change_id",
    "timestamp",
    "title",
    "description",
    "requested_by",
    "status",
    "type",
)

_OPTIONALE_FELDER = (
    "created_at",
    "diff_or_patch",
    "files_affected",
    "rollback_plan",
    "test_plan",
    "related_approval_id",
    "related_event_id",
    "risk_category",
    "risk_score",
    "decided_at",
    "decided_by",
    "decision_reason",
    "deployed_at",
    "rolled_back_at",
)

_ERLAUBTE_FELDER = frozenset(_PFLICHT_FELDER) | frozenset(_OPTIONALE_FELDER)


class ChangeParserError(ValueError):
    """JSON entspricht nicht dem Change-Request-Schema."""


# ---------------------------------------------------------------------- #
# Dikt -> ChangeRequest
# ---------------------------------------------------------------------- #

def _require_key(d: Mapping[str, Any], key: str) -> Any:
    if key not in d:
        raise ChangeParserError(f"Pflichtfeld fehlt: {key}")
    return d[key]


def _reject_unknown(d: Mapping[str, Any]) -> None:
    unknown = set(d) - _ERLAUBTE_FELDER
    if unknown:
        raise ChangeParserError(
            f"unbekannte Felder: {sorted(unknown)}"
        )


def change_from_dict(d: Mapping[str, Any]) -> ChangeRequest:
    """
    Baut einen ChangeRequest aus einem Dikt.
    Fail closed: fehlende Pflichtfelder, unbekannte Felder,
    falsche Enum-Werte, naive Zeitstempel -> ChangeParserError.
    """
    if not isinstance(d, Mapping):
        raise ChangeParserError(
            f"Erwartet Mapping, nicht {type(d).__name__}"
        )
    _reject_unknown(d)

    for key in _PFLICHT_FELDER:
        if key not in d:
            raise ChangeParserError(f"Pflichtfeld fehlt: {key}")

    # Enums
    try:
        status = ChangeStatus(_require_key(d, "status"))
    except ValueError as exc:
        raise ChangeParserError(
            f"status ungueltig: {d.get('status')!r}"
        ) from exc
    try:
        type_ = ChangeType(_require_key(d, "type"))
    except ValueError as exc:
        raise ChangeParserError(
            f"type ungueltig: {d.get('type')!r}"
        ) from exc

    # Strings
    for key in ("change_id", "title", "description", "requested_by"):
        v = _require_key(d, key)
        if not isinstance(v, str) or not v.strip():
            raise ChangeParserError(
                f"{key} muss nicht-leerer String sein"
            )

    # Pflicht-Zeitstempel
    ts = _require_key(d, "timestamp")
    try:
        require_utc_iso(ts, "timestamp")
    except ValueError as exc:
        raise ChangeParserError(str(exc)) from exc

    # Optionale Zeitstempel
    for key in ("decided_at", "deployed_at", "rolled_back_at"):
        v = d.get(key)
        if v is None:
            continue
        try:
            require_utc_iso(v, key)
        except ValueError as exc:
            raise ChangeParserError(str(exc)) from exc

    # files_affected
    files = d.get("files_affected")
    if files is not None and (not isinstance(files, list) or not all(
            isinstance(x, str) for x in files)):
        raise ChangeParserError(
            "files_affected muss Liste von Strings sein"
        )

    # risk_score
    rs = d.get("risk_score")
    if rs is not None and not isinstance(rs, (int, float)):
        raise ChangeParserError("risk_score muss Zahl sein")

    try:
        return ChangeRequest(
            change_id=d["change_id"],
            timestamp=ts,
            title=d["title"],
            description=d["description"],
            requested_by=d["requested_by"],
            status=status,
            type=type_,
            created_at=d.get("created_at") or utc_now_iso(),
            diff_or_patch=d.get("diff_or_patch"),
            files_affected=files,
            rollback_plan=d.get("rollback_plan"),
            test_plan=d.get("test_plan"),
            related_approval_id=d.get("related_approval_id"),
            related_event_id=d.get("related_event_id"),
            risk_category=d.get("risk_category"),
            risk_score=rs,
            decided_at=d.get("decided_at"),
            decided_by=d.get("decided_by"),
            decision_reason=d.get("decision_reason"),
            deployed_at=d.get("deployed_at"),
            rolled_back_at=d.get("rolled_back_at"),
        )
    except ValueError as exc:
        raise ChangeParserError(str(exc)) from exc


# ---------------------------------------------------------------------- #
# ChangeRequest -> Dikt / JSON
# ---------------------------------------------------------------------- #

def change_to_dict(cr: ChangeRequest) -> dict[str, Any]:
    """
    Repraesentation fuer den JSON-Export.
    Entfernt das DB-interne id-Feld, damit Export stabil bleibt.
    """
    d = cr.to_dict()
    d.pop("id", None)
    return d


def change_to_json(cr: ChangeRequest, indent: int = 2) -> str:
    """Serialisiert ChangeRequest als JSON-String."""
    return json.dumps(
        change_to_dict(cr), indent=indent, ensure_ascii=False,
        sort_keys=False,
    )


# ---------------------------------------------------------------------- #
# Datei-I/O
# ---------------------------------------------------------------------- #

def default_path(change_id: str, base_dir: str | Path = DEFAULT_CHANGES_DIR
                 ) -> Path:
    """
    Konvention: <base_dir>/<change_id>.json.
    Prueft, dass change_id keine Pfad-Trenner enthaelt (fail closed).
    """
    if not isinstance(change_id, str) or not change_id:
        raise ChangeParserError("change_id darf nicht leer sein")
    for bad in ("/", "\\", "..", "\x00"):
        if bad in change_id:
            raise ChangeParserError(
                f"change_id enthaelt unerlaubtes Zeichen: {bad!r}"
            )
    return Path(base_dir) / f"{change_id}.json"


def write_change_file(
    cr: ChangeRequest,
    base_dir: str | Path = DEFAULT_CHANGES_DIR,
) -> Path:
    """Schreibt ChangeRequest als JSON-Datei. Liefert den Pfad."""
    path = default_path(cr.change_id, base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(change_to_json(cr), encoding="utf-8")
    return path


def read_change_file(
    path: str | Path,
) -> ChangeRequest:
    """Liest eine JSON-Datei und baut einen ChangeRequest."""
    p = Path(path)
    if not p.exists():
        raise ChangeParserError(f"Datei nicht gefunden: {p}")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (TypeError, ValueError) as exc:
        raise ChangeParserError(f"JSON nicht parsebar: {exc}") from exc
    return change_from_dict(raw)


__all__ = [
    "DEFAULT_CHANGES_DIR",
    "ChangeParserError",
    "change_from_dict",
    "change_to_dict",
    "change_to_json",
    "default_path",
    "read_change_file",
    "write_change_file",
]
