# Copyright (C) 2026 Alexander Nohl
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Policy Engine.

Laedt policies/tools.yaml und bewertet Tool-Aufrufe.

Zwei Kategorien von Pruefern:

  GLOBAL_PREDICATES    laufen IMMER, unabhaengig von der Policy.
                       Sie koennen nicht durch vergessene
                       conditions ausgehebelt werden.

  SPECIFIC_PREDICATES  laufen nur, wenn die Policy sie in
                       conditions nennt.

Pruef-Reihenfolge in evaluate():
  a) Tool nicht in Policy -> FORBIDDEN (fail closed)
  b) GLOBAL_PREDICATES
  c) forbidden_args (Praesenz in args)
  d) SPECIFIC_PREDICATES aus conditions
  e) strengste Entscheidung -> PolicyDecision

Kein eval, kein DSL. Unbekannter Pruefer-Name -> PolicyError.
Kein DB-Zugriff.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:
    import yaml  # PyYAML
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "PyYAML wird gebraucht. Installieren mit: apt install python3-yaml"
    ) from exc

from harness.policy_engine.policy import (
    Decision,
    PolicyContext,
    PolicyDecision,
    PolicyError,
    PredicateResult,
    allowed,
    approval,
    forbidden,
    strictest,
)

Predicate = Callable[[dict[str, Any], PolicyContext], PredicateResult]


# ---------------------------------------------------------------------- #
# Pruefer
# ---------------------------------------------------------------------- #

# Shell-Metazeichen, die in Argumenten verboten sind.
_SHELL_CHARS = (";", "|", "&", "$", "`", "\n", "\r", ">", "<", "(", ")")


def _pred_authorized_target(
    args: dict[str, Any], ctx: PolicyContext,
) -> PredicateResult:
    """Weich: args["target"] muss in ctx.authorized_networks stehen."""
    target = args.get("target")
    if not target or not isinstance(target, str):
        return PredicateResult(
            passed=False,
            on_fail=Decision.APPROVAL_REQUIRED,
            reason="kein Ziel angegeben",
        )
    if not ctx.authorized_networks:
        return PredicateResult(
            passed=False,
            on_fail=Decision.APPROVAL_REQUIRED,
            reason="keine authorized_networks im Kontext",
        )
    if ctx.has_network(target):
        return PredicateResult(passed=True)
    return PredicateResult(
        passed=False,
        on_fail=Decision.APPROVAL_REQUIRED,
        reason=f"Ziel {target!r} nicht in authorized_networks",
    )


def _pred_read_only_path(
    args: dict[str, Any], ctx: PolicyContext,
) -> PredicateResult:
    """Weich: args["path"] muss unter ctx.config["read_only_paths"] liegen."""
    path = args.get("path")
    if not path or not isinstance(path, str):
        return PredicateResult(
            passed=False,
            on_fail=Decision.APPROVAL_REQUIRED,
            reason="kein Pfad angegeben",
        )
    roots = (ctx.config or {}).get("read_only_paths") or []
    if not roots:
        return PredicateResult(
            passed=False,
            on_fail=Decision.APPROVAL_REQUIRED,
            reason="keine read_only_paths im Kontext",
        )
    norm = str(Path(path))
    for root in roots:
        root_norm = str(Path(root))
        if norm == root_norm or norm.startswith(root_norm.rstrip("/") + "/"):
            return PredicateResult(passed=True)
    return PredicateResult(
        passed=False,
        on_fail=Decision.APPROVAL_REQUIRED,
        reason=f"Pfad {path!r} nicht unter read_only_paths",
    )


def _pred_no_shell_chars(
    args: dict[str, Any], ctx: PolicyContext,
) -> PredicateResult:
    """Hart: kein Shell-Metazeichen in irgendeinem Wert."""
    text = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
    for ch in _SHELL_CHARS:
        if ch in text:
            return PredicateResult(
                passed=False,
                on_fail=Decision.FORBIDDEN,
                reason=f"Shell-Metazeichen {ch!r} in Argumenten",
            )
    return PredicateResult(passed=True)


def _pred_no_path_traversal(
    args: dict[str, Any], ctx: PolicyContext,
) -> PredicateResult:
    """Hart: kein '..' oder URL-encoded '..' in irgendeinem Wert."""
    text = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
    low = text.lower()
    for marker in ("..", "%2e%2e"):
        if marker in low:
            return PredicateResult(
                passed=False,
                on_fail=Decision.FORBIDDEN,
                reason=f"Path-Traversal-Marker {marker!r} in Argumenten",
            )
    return PredicateResult(passed=True)


def _pred_no_null_bytes(
    args: dict[str, Any], ctx: PolicyContext,
) -> PredicateResult:
    """Hart: keine Null-Bytes in irgendeinem Wert."""
    text = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
    if "\x00" in text or "\\u0000" in text:
        return PredicateResult(
            passed=False,
            on_fail=Decision.FORBIDDEN,
            reason="Null-Byte in Argumenten",
        )
    return PredicateResult(passed=True)


def _pred_target_in_scope(
    args: dict[str, Any], ctx: PolicyContext,
) -> PredicateResult:
    """Weich: Ziel-IP muss in einer der ctx.authorized_networks-CIDRs liegen."""
    import ipaddress

    target = args.get("target") or args.get("dst_ip")
    if not target or not isinstance(target, str):
        return PredicateResult(
            passed=False,
            on_fail=Decision.APPROVAL_REQUIRED,
            reason="kein Ziel angegeben",
        )
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return PredicateResult(
            passed=False,
            on_fail=Decision.APPROVAL_REQUIRED,
            reason=f"Ziel {target!r} ist keine gueltige IP",
        )
    for c in ctx.authorized_networks:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if ip in net:
            return PredicateResult(passed=True)
    return PredicateResult(
        passed=False,
        on_fail=Decision.APPROVAL_REQUIRED,
        reason=f"Ziel {target!r} ausserhalb authorized_networks",
    )


# Globale Pruefer laufen IMMER, unabhaengig von der Policy.
# Sie koennen nicht durch vergessene conditions ausgehebelt werden.
GLOBAL_PREDICATES: dict[str, Predicate] = {
    "no_shell_chars": _pred_no_shell_chars,
    "no_path_traversal": _pred_no_path_traversal,
    "no_null_bytes": _pred_no_null_bytes,
}

# Spezifische Pruefer laufen nur, wenn die Policy sie in
# conditions nennt.
SPECIFIC_PREDICATES: dict[str, Predicate] = {
    "authorized_target": _pred_authorized_target,
    "read_only_path": _pred_read_only_path,
    "target_in_scope": _pred_target_in_scope,
}


def all_predicate_names() -> set[str]:
    """Menge aller bekannten Pruefer-Namen (global + spezifisch)."""
    return set(GLOBAL_PREDICATES) | set(SPECIFIC_PREDICATES)


def get_predicate(name: str) -> tuple[Predicate, str]:
    """
    Liefert (Pruefer-Funktion, Kategorie) fuer einen Namen.

    Kategorie ist "global" oder "specific".
    Unbekannter Name -> PolicyError.
    """
    if name in GLOBAL_PREDICATES:
        return GLOBAL_PREDICATES[name], "global"
    if name in SPECIFIC_PREDICATES:
        return SPECIFIC_PREDICATES[name], "specific"
    raise PolicyError(f"Unbekannter Pruefer: {name!r}")


# ---------------------------------------------------------------------- #
# Engine
# ---------------------------------------------------------------------- #

class PolicyEngine:
    """
    Bewertet Tool-Aufrufe gegen policies/tools.yaml.

    Format (Beispiel):

        tools:
          nmap_scan:
            allowed: true
            level: 1
            conditions:
              - authorized_target
            forbidden_args: ["--script", "-oA"]
            reason: "Nmap nur gegen autorisierte Netze"

    Globale Pruefer duerfen nicht in conditions stehen (PolicyError
    beim Laden).
    """

    def __init__(self, rules_path: Path | str = "policies/tools.yaml") -> None:
        self._path = Path(rules_path)
        self._rules: dict[str, dict[str, Any]] = {}
        self._load()

    # ------------------------------------------------------------------ #
    # Laden
    # ------------------------------------------------------------------ #

    def _load(self) -> None:
        if not self._path.exists():
            raise PolicyError(f"Policy-Datei fehlt: {self._path}")

        with self._path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}

        if not isinstance(data, dict):
            raise PolicyError("Policy-Datei: top-level muss ein Mapping sein")

        tools = data.get("tools")
        if not isinstance(tools, dict):
            raise PolicyError("Policy-Datei: 'tools' fehlt oder ist kein Mapping")

        for name, rule in tools.items():
            if not isinstance(name, str):
                raise PolicyError(f"Tool-Name muss String sein: {name!r}")
            self._validate_rule(name, rule)
        self._rules = tools

    def _validate_rule(self, name: str, rule: Any) -> None:
        if not isinstance(rule, dict):
            raise PolicyError(f"Policy {name!r}: muss ein Mapping sein")

        # conditions: nur spezifische Pruefer erlaubt
        conds = rule.get("conditions", [])
        if not isinstance(conds, list):
            raise PolicyError(f"Policy {name!r}: 'conditions' muss Liste sein")
        for c in conds:
            _fn, kind = get_predicate(c)  # PolicyError bei unbekannt
            if kind == "global":
                raise PolicyError(
                    f"Policy {name!r}: {c!r} ist ein globaler Pruefer "
                    "und darf nicht in conditions stehen"
                )

        # forbidden_args: Liste von Strings
        fa = rule.get("forbidden_args", [])
        if not isinstance(fa, list) or not all(isinstance(x, str) for x in fa):
            raise PolicyError(
                f"Policy {name!r}: 'forbidden_args' muss Liste von Strings sein"
            )

        # allowed: bool
        if "allowed" in rule and not isinstance(rule["allowed"], bool):
            raise PolicyError(f"Policy {name!r}: 'allowed' muss bool sein")

        # level: int 0-5
        if "level" in rule:
            lvl = rule["level"]
            if not isinstance(lvl, int) or lvl < 0 or lvl > 5:
                raise PolicyError(
                    f"Policy {name!r}: 'level' muss int 0-5 sein"
                )

    # ------------------------------------------------------------------ #
    # Bewerten
    # ------------------------------------------------------------------ #

    def evaluate(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        context: PolicyContext | None = None,
    ) -> PolicyDecision:
        """
        Pruef-Reihenfolge:
          a) Tool nicht in Policy -> FORBIDDEN
          b) GLOBAL_PREDICATES (immer)
          c) forbidden_args -> FORBIDDEN (frueh raus)
          d) SPECIFIC_PREDICATES aus conditions
          e) strengste Entscheidung -> PolicyDecision
        """
        args = args or {}
        ctx = context or PolicyContext()

        rule = self._rules.get(tool_name)
        if rule is None:
            return forbidden(
                tool_name=tool_name,
                reason=f"Tool {tool_name!r} nicht in Policy",
                level=0,
            )

        level = int(rule.get("level", 0))
        matched_rule = tool_name

        # a) allowed=False
        if rule.get("allowed") is False:
            return forbidden(
                tool_name=tool_name,
                reason=str(rule.get("reason", "Tool nicht erlaubt")),
                level=level,
                matched_rule=matched_rule,
            )

        # b) globale Pruefer (immer)
        current = Decision.ALLOWED
        failed: list[str] = []
        reasons: list[str] = []

        for name, fn in GLOBAL_PREDICATES.items():
            try:
                res = fn(args, ctx)
            except Exception as exc:  # noqa: BLE001
                res = PredicateResult(
                    passed=False,
                    on_fail=Decision.FORBIDDEN,
                    reason=f"globaler Pruefer {name!r} warf Exception: {exc!r}",
                )
            if not res.passed:
                failed.append(name)
                if res.reason:
                    reasons.append(f"{name}: {res.reason}")
                current = strictest(current, res.on_fail)
            if current is Decision.FORBIDDEN:
                # harter Treffer: sofort raus
                return forbidden(
                    tool_name=tool_name,
                    reason="; ".join(reasons),
                    level=level,
                    matched_rule=matched_rule,
                    failed=failed,
                )

        # c) forbidden_args (Praesenz der Schluessel in args)
        fa = rule.get("forbidden_args") or []
        for bad in fa:
            if bad in args:
                return forbidden(
                    tool_name=tool_name,
                    reason=f"verbotenes Argument {bad!r} im Aufruf",
                    level=level,
                    matched_rule=matched_rule,
                    failed=failed + ["forbidden_args"],
                )

        # d) spezifische Pruefer aus conditions
        conditions = rule.get("conditions", [])
        for cond_name in conditions:
            fn, _kind = get_predicate(cond_name)
            try:
                res = fn(args, ctx)
            except Exception as exc:  # noqa: BLE001
                res = PredicateResult(
                    passed=False,
                    on_fail=Decision.APPROVAL_REQUIRED,
                    reason=f"Pruefer {cond_name!r} warf Exception: {exc!r}",
                )
            if not res.passed:
                failed.append(cond_name)
                if res.reason:
                    reasons.append(f"{cond_name}: {res.reason}")
                current = strictest(current, res.on_fail)

        # e) Ergebnis
        if current is Decision.ALLOWED:
            base_reason = (
                "alle Bedingungen erfuellt"
                if conditions
                else "keine Conditions definiert"
            )
            return allowed(
                tool_name=tool_name,
                level=level,
                matched_rule=matched_rule,
                reason=base_reason,
            )

        if current is Decision.FORBIDDEN:
            return forbidden(
                tool_name=tool_name,
                reason="; ".join(reasons) or "Policy verbietet Aufruf",
                level=level,
                matched_rule=matched_rule,
                failed=failed,
            )

        return approval(
            tool_name=tool_name,
            reason="; ".join(reasons) or "Freigabe erforderlich",
            level=level,
            matched_rule=matched_rule,
            failed=failed,
        )

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #

    @property
    def known_tools(self) -> set[str]:
        return set(self._rules.keys())

    def has_tool(self, tool_name: str) -> bool:
        return tool_name in self._rules


__all__ = [
    "GLOBAL_PREDICATES",
    "SPECIFIC_PREDICATES",
    "PolicyEngine",
    "all_predicate_names",
    "get_predicate",
]
