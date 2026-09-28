"""
Regel: port_scan.

Stateful. Triggert auf connection_attempt / syn_packet und erkennt
drei Muster pro Quell-IP:

  - port_scan:     viele verschiedene Ziel-Ports in kurzer Zeit
  - network_scan:  viele verschiedene Ziel-IPs in kurzer Zeit
  - brute_force:   viele Versuche auf denselben Port

Zustand liegt im RuleContext.state (Ringpuffer pro src_ip).
Dedup: pro src_ip wird hoechstens einmal pro alert_cooldown_seconds
alarmiert.
"""
from __future__ import annotations

from typing import Any

from core.detection.rule_base import Rule, RuleContext
from core.events.event import Event, EventType, Severity, new_event

_TRIGGER_TYPES = frozenset({
    EventType.CONNECTION_ATTEMPT.value,
    EventType.SYN_PACKET.value,
})

_DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "severity": "WARNING",
    "distinct_ports_threshold": 10,
    "window_seconds": 60,
    "distinct_ips_threshold": 5,
    "distinct_ips_window_seconds": 120,
    "same_port_attempts_threshold": 20,
    "same_port_window_seconds": 30,
    "alert_cooldown_seconds": 300,
    "trust_whitelisted_sources": False,
}


def _cfg(config: dict[str, Any], key: str) -> Any:
    """Liest einen Config-Wert mit Fallback auf _DEFAULTS."""
    if key in config:
        return config[key]
    return _DEFAULTS[key]


class PortScanRule(Rule):
    id = "port_scan"
    event_types = _TRIGGER_TYPES
    severity = Severity.WARNING
    description = (
        "Erkennt Port-Scans, Netzwerk-Scans und Brute-Force-Versuche "
        "pro Quell-IP anhand von Schwellwerten in rules.yaml."
    )

    # ------------------------------------------------------------------ #
    # evaluate
    # ------------------------------------------------------------------ #

    def evaluate(self, event: Event, context: RuleContext) -> list[Event]:
        if event.event_type not in self.event_types:
            return []

        cfg = context.config or {}
        if not _cfg(cfg, "enabled"):
            return []

        src_ip = event.data.get("src_ip")
        dst_ip = event.data.get("dst_ip")
        dst_port = event.data.get("dst_port")

        # Ohne src_ip / dst_port kein Zustand moeglich.
        if not src_ip or dst_port is None:
            return []

        state = context.state
        bucket_key = f"ps:{src_ip}"

        # 1) Event in den Ringpuffer.
        state.record(bucket_key, {
            "ts": event.timestamp,
            "port": dst_port,
            "dst_ip": dst_ip,
        })

        entries = state.get(bucket_key)
        now = context.now

        # 2) Fenster pruefen.
        # Fenster gegen event.timestamp (deterministisch, replay-faehig).
        # Cooldown bleibt gegen context.now (Wall-Clock).
        kind, ports_seen, ips_seen = self._classify(
            entries, event.timestamp, cfg
        )
        if kind is None:
            return []

        # 3) Cooldown pro src_ip.
        cooldown = _cfg(cfg, "alert_cooldown_seconds")
        last_key = f"ps_last:{src_ip}"
        last = state.get(last_key)
        if last:
            last_ts = last[-1]
            try:
                delta = (now - last_ts).total_seconds()
            except TypeError:
                delta = cooldown + 1  # unvergleichbar -> Cooldown ignorieren
            if 0 <= delta < cooldown:
                return []

        state.record(last_key, now)

        # 4) Output-Event.
        severity_name = _cfg(cfg, "severity")
        try:
            severity = Severity(severity_name)
        except ValueError:
            severity = Severity.WARNING

        from core.events.event import Event as _Event
        from core.events.event import new_event_id
        return [
            _Event(
                event_id=new_event_id(),
                timestamp=event.timestamp,
                source=f"detection:{self.id}",
                event_type=EventType.PORT_SCAN.value,
                severity=severity,
                data={
                    "identifier": src_ip,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "kind": kind,
                    "ports_seen": ports_seen,
                    "ips_seen": ips_seen,
                    "window_s": self._window_for(kind, cfg),
                    "network_type": event.data.get("network_type"),
                    "trigger_event_id": event.event_id,
                },
                network_id=event.network_id,
            )
        ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _classify(
        self,
        entries: list[dict[str, Any]],
        now: Any,
        cfg: dict[str, Any],
    ) -> tuple[str | None, int, int]:
        """
        Prueft die drei Muster in Prioritaet:
          1) distinct_ports  -> port_scan
          2) distinct_ips    -> network_scan
          3) same_port_count -> brute_force
        Rueckgabe: (kind, ports_seen, ips_seen).
        """
        max_window = max(
            _cfg(cfg, "window_seconds"),
            _cfg(cfg, "distinct_ips_window_seconds"),
            _cfg(cfg, "same_port_window_seconds"),
        )
        recent = self._within(entries, now, max_window)

        # 1) distinct_ports
        win = _cfg(cfg, "window_seconds")
        thr = _cfg(cfg, "distinct_ports_threshold")
        sub = self._within(recent, now, win)
        ports = {e["port"] for e in sub}
        ips_all = {e.get("dst_ip") for e in sub if e.get("dst_ip")}
        if len(ports) >= thr:
            return "port_scan", len(ports), len(ips_all)

        # 2) distinct_ips
        win = _cfg(cfg, "distinct_ips_window_seconds")
        thr = _cfg(cfg, "distinct_ips_threshold")
        sub = self._within(recent, now, win)
        ips = {e.get("dst_ip") for e in sub if e.get("dst_ip")}
        ports_in_sub = {e["port"] for e in sub}
        if len(ips) >= thr:
            return "network_scan", len(ports_in_sub), len(ips)

        # 3) same_port_attempts
        win = _cfg(cfg, "same_port_window_seconds")
        thr = _cfg(cfg, "same_port_attempts_threshold")
        sub = self._within(recent, now, win)
        counts: dict[Any, int] = {}
        for e in sub:
            counts[e["port"]] = counts.get(e["port"], 0) + 1
        if counts:
            _top_port, top_n = max(counts.items(), key=lambda kv: kv[1])
            if top_n >= thr:
                ports_in_sub = {e["port"] for e in sub}
                ips_in_sub = {e.get("dst_ip") for e in sub if e.get("dst_ip")}
                return "brute_force", len(ports_in_sub), len(ips_in_sub)

        return None, len(ports), len(ips_all)

    def _window_for(self, kind: str, cfg: dict[str, Any]) -> int:
        if kind == "port_scan":
            return _cfg(cfg, "window_seconds")
        if kind == "network_scan":
            return _cfg(cfg, "distinct_ips_window_seconds")
        return _cfg(cfg, "same_port_window_seconds")

    @staticmethod
    def _within(
        entries: list[dict[str, Any]],
        now: Any,
        window_seconds: int,
    ) -> list[dict[str, Any]]:
        """Filtert Eintraege, deren ts innerhalb der letzten window_seconds liegt."""
        if window_seconds <= 0:
            return list(entries)
        out: list[dict[str, Any]] = []
        for e in entries:
            ts = e.get("ts")
            if ts is None:
                continue
            try:
                delta = (now - ts).total_seconds()
            except TypeError:
                continue
            if 0 <= delta <= window_seconds:
                out.append(e)
        return out


__all__ = ["PortScanRule"]
