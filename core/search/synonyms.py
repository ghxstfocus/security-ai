"""
Synonym-Erweiterung fuer die Suche (Punkt 29).

Auflagen 776-790, Variante 2.

Laedt synonyms.yaml und erweitert einen
Suchbegriff auf die Zielwerte, wenn der Begriff
ein Synonym eines Zielwerts ist.

Regeln:
- yaml.safe_load (Auflage 777).
- Unbekannte Zielwerte in risk_category
  -> SearchServiceError (Auflage 788, fail closed).
- expand_query gibt immer eine Liste zurueck,
  mindestens den Originalbegriff.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from core.risk.models import RiskCategory
from core.services import ServiceError


DEFAULT_SYNONYMS_PATH = Path("core/search/synonyms.yaml")


class SynonymError(ServiceError):
    """Fehler beim Laden oder Erweitern der Synonyme."""


def load_synonyms(
    path: Path | str = DEFAULT_SYNONYMS_PATH,
) -> dict[str, dict[str, list[str]]]:
    """
    Liest die YAML und validiert die Struktur.

    Fail closed: kaputte YAML oder unbekannte
    RiskCategory-Werte -> SynonymError.
    """
    p = Path(path)
    if not p.is_file():
        raise SynonymError(f"Synonym-Datei fehlt: {p}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SynonymError(f"YAML unlesbar: {exc}") from exc
    if not isinstance(data, dict):
        raise SynonymError("YAML-Wurzel muss ein dict sein")

    # Validierung risk_category (Auflage 788).
    rc = data.get("risk_category")
    if rc is not None:
        if not isinstance(rc, dict):
            raise SynonymError("risk_category muss dict sein")
        bekannt = {c.value for c in RiskCategory}
        for wert in rc:
            if wert not in bekannt:
                raise SynonymError(
                    f"Unbekannte RiskCategory: {wert!r}"
                )
    return data


def expand_query(
    query: str,
    field: str,
    synonyms: dict[str, dict[str, list[str]]],
) -> list[str]:
    """
    Liefert [query] plus Zielwerte, deren Synonyme
    der query entsprechen (case-insensitiv).

    Mindestens [query]. Unbekanntes Feld -> [query].
    """
    if not isinstance(query, str) or not query:
        return []
    q_lower = query.lower()
    ergebnis: list[str] = [query]
    gesehen: set[str] = {query.lower()}

    feld_map = synonyms.get(field)
    if not isinstance(feld_map, dict):
        return ergebnis

    for zielwert, synonyme in feld_map.items():
        if not isinstance(synonyme, list):
            continue
        for syn in synonyme:
            if not isinstance(syn, str):
                continue
            if syn.lower() == q_lower:
                if zielwert.lower() not in gesehen:
                    ergebnis.append(zielwert)
                    gesehen.add(zielwert.lower())
                break

    return ergebnis


__all__ = [
    "DEFAULT_SYNONYMS_PATH",
    "SynonymError",
    "expand_query",
    "load_synonyms",
]
