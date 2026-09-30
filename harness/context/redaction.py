"""
Prompt-Injection-Schutz fuer den Kontext-Bauer.

Aufgabe: Rohdaten (Events, Logs, DB-Felder) so filtern, dass
das lokale LLM keine Instruktionen aus unbekannten Quellen
ausfuehren kann.

Regeln (fail closed):
- Steuerzeichen entfernen (\\x00, \\r, \\x0b, \\x0c).
- Instruktions-Marker entfernen (case-insensitive):
  "ignore previous", "ignore all", "system:", "assistant:",
  "user:", "<|im_start|>", "<|im_end|>", "###instruction",
  "[INST]", "[/INST]", "<<SYS>>", "<</SYS>>".
- Laenge pro Feld begrenzen (max_len, Default 2000 Zeichen).
- Bei Verstoss: betroffene Passage durch [REDACTED] ersetzen.

redact_text liefert (sauberer_text, wurde_redigiert).
redact_field ist der Wrapper fuer ein einzelnes Feld mit
Laengenbegrenzung.
"""
from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------- #
# Konstanten
# ---------------------------------------------------------------------- #

MAX_FIELD_LEN = 2000

_REDACTION_PLACEHOLDER = "[REDACTED]"

# Steuerzeichen, die in Textfeldern nichts zu suchen haben.
# \\t und \\n bleiben (mehrzeilige Logs sind erlaubt).
_CONTROL_CHARS_RE = re.compile(r"[\x00\r\x0b\x0c]")

# Instruktions-Marker. Case-insensitive. Werden durch
# [REDACTED] ersetzt.
_INJECTION_MARKERS = (
    "ignore previous",
    "ignore all",
    "ignore the above",
    "system:",
    "assistant:",
    "user:",
    "<|im_start|>",
    "<|im_end|>",
    "###instruction",
    "[inst]",
    "[/inst]",
    "<<sys>>",
    "<</sys>>",
)

# Ein Regex, der alle Marker in einem Durchgang findet.
_INJECTION_RE = re.compile(
    "|".join(re.escape(m) for m in _INJECTION_MARKERS),
    re.IGNORECASE,
)


# ---------------------------------------------------------------------- #
# Oeffentliche API
# ---------------------------------------------------------------------- #

def redact_text(text: str, *, max_len: int = MAX_FIELD_LEN
                ) -> tuple[str, bool]:
    """
    Filtert einen Text und liefert (sauberer_text, wurde_redigiert).

    - None/nicht-String -> ("", True) (fail closed, markiert als redigiert)
    - Steuerzeichen entfernt
    - Instruktions-Marker ersetzt
    - Laenge auf max_len gekuerzt (Ueberlaenge wird als Redaktion gezaehlt)
    """
    if not isinstance(text, str):
        return ("", True)
    if max_len < 0:
        raise ValueError("redact_text: max_len muss >= 0 sein")

    redacted = False
    out = text

    # Steuerzeichen
    cleaned = _CONTROL_CHARS_RE.sub("", out)
    if cleaned != out:
        redacted = True
        out = cleaned

    # Instruktions-Marker
    substituted = _INJECTION_RE.sub(_REDACTION_PLACEHOLDER, out)
    if substituted != out:
        redacted = True
        out = substituted

    # Laenge
    if len(out) > max_len:
        out = out[:max_len] + _REDACTION_PLACEHOLDER
        redacted = True

    return (out, redacted)


def redact_field(value: object, *, max_len: int = MAX_FIELD_LEN
                 ) -> tuple[str, bool]:
    """
    Wrapper fuer ein einzelnes Feld.

    Akzeptiert str, int, float, bool, None. Alles andere -> "" + redigiert.
    """
    if value is None:
        return ("", False)
    if isinstance(value, str):
        return redact_text(value, max_len=max_len)
    if isinstance(value, (int, float, bool)):
        return (str(value), False)
    # dict, list, Objekte: nicht inline rendern (fail closed)
    return ("", True)


def redact_mapping(
    data: dict, *, max_len: int = MAX_FIELD_LEN
) -> tuple[dict[str, Any], bool]:
    """
    Filtert ein dict[str, Any] auf dict[str, Any].
    Skalare werden per redact_field stringifiziert,
    Listen/Objekte fail closed (leerer String,
    redigiert). Liefert (sauberes_dict, wurde_redigiert).
    """
    if not isinstance(data, dict):
        return ({}, True)
    out: dict[str, Any] = {}
    redacted = False
    for k, v in data.items():
        if not isinstance(k, str):
            redacted = True
            continue
        cleaned, was = redact_field(v, max_len=max_len)
        if was:
            redacted = True
        out[k] = cleaned
    return (out, redacted)


__all__ = [
    "MAX_FIELD_LEN",
    "redact_field",
    "redact_mapping",
    "redact_text",
]
