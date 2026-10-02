# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Link-Erkennung fuer Chat-Antworten (Punkt 30).

Auflagen 757-772, Variante 4.

Erkennt IDs in einer fact-/detail_append-Antwort
und liefert eine Liste {label, href}. Prueft
RBAC pro Link.

Sicherheit:
- Kein Href aus dem Text. Der Href wird aus
  der erkannten ID gebaut (Auflage 763).
- Nur interne Links (Auflage 761, 762).
- Label ist der Rohstring (Auflage 764).
- LLM-Antworten werden NICHT durchsucht
  (Auflage 758).
"""
from __future__ import annotations

import re

from core.access.checker import AccessChecker

# Erkannte ID-Muster. Reihenfolge ist wichtig:
# laengste/spezifischste zuerst.
_ID_PATTERNS = (
    # Audit-ID: AUD-YYYY-MM-DD-XXXXXXXX
    (
        re.compile(r"\bAUD-\d{4}-\d{2}-\d{2}-[0-9a-f]{8}\b"),
        lambda m: f"/audit/{m.group(0)}",
        "audit.read",
    ),
    # Change-ID: CHG-YYYY-NNNNN
    (
        re.compile(r"\bCHG-\d{4}-\d{5}\b"),
        lambda m: f"/changes/{m.group(0)}",
        "change.view",
    ),
    # Approval-ID: APR-YYYY-NNNNN
    (
        re.compile(r"\bAPR-\d{4}-\d{5}\b"),
        lambda m: f"/approvals/{m.group(0)}",
        "approval.view",
    ),
    # IP-Adresse (nur IPv4). Inventory-Kennung.
    (
        re.compile(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ),
        lambda m: f"/inventory/{m.group(0)}",
        "device.read",
    ),
)

# Sicherheitsnetz: nur Pfade, die mit "/" beginnen
# und einem erlaubten Praefix folgen (Auflage 761).
_ALLOWED_PREFIXES = (
    "/audit/",
    "/changes/",
    "/approvals/",
    "/inventory/",
    "/users/",
    "/roles/",
)

# A880: exakte Pfade ohne ID-Suffix. /alerts ist eine
# Aggregat-Ansicht, kein /alerts/<id>.
_ALLOWED_EXACT = (
    "/alerts",
)


def _is_allowed_href(href: str) -> bool:
    if not isinstance(href, str):
        return False
    if not href.startswith("/"):
        return False
    if href in _ALLOWED_EXACT:
        return True
    return any(href.startswith(p) for p in _ALLOWED_PREFIXES)


def extract_links(
    text: str,
    principal: str,
    checker: AccessChecker,
) -> list[dict[str, str]]:
    """
    Liefert eine Liste von {label, href} aus dem Text.

    Dedup (Auflage 759): jede ID erscheint maximal einmal.
    Reihenfolge (Auflage 760): erstes Vorkommen im Text.
    RBAC (Auflage 770): nur Links, die der Principal
    sehen darf.
    """
    if not isinstance(text, str) or not text:
        return []
    gesehen: set[str] = set()
    treffer: list[tuple[int, str, str]] = []  # (pos, label, href)

    for regex, build_href, permission in _ID_PATTERNS:
        for m in regex.finditer(text):
            label = m.group(0)
            if label in gesehen:
                continue
            gesehen.add(label)
            href = build_href(m)
            if not _is_allowed_href(href):
                continue
            if not checker.check(principal, permission):
                continue
            treffer.append((m.start(), label, href))

    treffer.sort(key=lambda t: t[0])
    return [{"label": lbl, "href": href} for _, lbl, href in treffer]


__all__ = ["extract_links"]
