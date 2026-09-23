"""
RateLimitService: In-Memory Rate-Limit pro Principal.

Zweck: /api/chat ist ein LLM-Konsum-Kanal. Ohne Limit
kann ein einzelner Principal den Container saettigen (DoS).

Design:
- Key = principal_name (nicht Session-ID, nicht IP).
  Begruendung: Zwei Sessions desselben Principals
  teilen das Limit; ein Relogin setzt es nicht zurueck.
- In-Memory dict {principal: list[float]}.
- Lock um dict-Zugriff (thread-safe).
- Single-Process heute (Flask dev, ein Worker).
  Bei Multi-Worker spaeter: gemeinsamer Store
  (Redis oder DB). NICHT Teil von 3.6.8e.
- Kein Audit, kein Log bei Treffer (Auflage 101).
  Sonst fuellt ein Angreifer die Audit-Logs.
"""
from __future__ import annotations

import threading
import time

from core.services import ServiceError


WINDOW_SECONDS = 60
MAX_REQUESTS = 10


class RateLimitServiceError(ServiceError):
    """Fachlicher Fehler im RateLimitService."""


class RateLimitService:
    def __init__(
        self,
        *,
        window_seconds: int = WINDOW_SECONDS,
        max_requests: int = MAX_REQUESTS,
    ) -> None:
        if not isinstance(window_seconds, int) or window_seconds <= 0:
            raise RateLimitServiceError(
                "window_seconds muss positive int sein"
            )
        if not isinstance(max_requests, int) or max_requests <= 0:
            raise RateLimitServiceError(
                "max_requests muss positive int sein"
            )
        self._window = window_seconds
        self._max = max_requests
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, principal_name: str) -> tuple[bool, int]:
        """
        True, wenn Anfrage erlaubt.
        int = Retry-After-Sekunden (0 bei True).
        """
        if not isinstance(principal_name, str) or not principal_name:
            raise RateLimitServiceError(
                "principal_name darf nicht leer sein"
            )
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            hits = self._hits.get(principal_name, [])
            hits = [t for t in hits if t > cutoff]
            if len(hits) >= self._max:
                oldest = hits[0]
                retry_after = int(
                    self._window - (now - oldest)
                )
                if retry_after < 1:
                    retry_after = 1
                self._hits[principal_name] = hits
                return (False, retry_after)
            hits.append(now)
            self._hits[principal_name] = hits
            return (True, 0)


__all__ = [
    "MAX_REQUESTS",
    "WINDOW_SECONDS",
    "RateLimitService",
    "RateLimitServiceError",
]
