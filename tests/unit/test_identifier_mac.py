"""MAC als identifier-Wert (Punkt 42, Phase 3.8a).

Keine Schema-Aenderung. identifier bleibt TEXT.
MAC ist ein gueltiger Wert. Der Fritz!Box-Watcher
(Block 3.8a, spaeter) liefert MACs.

modulweite pytest-Funktionen, weil migrated_conn
tmp_path ueber die pytest-Fixture bezieht.
"""
from __future__ import annotations

from datetime import UTC, datetime

from core.detection.rule_base import RuleContext
from core.detection.rules.unknown_device import UnknownDeviceRule
from core.events.event import Event, EventType, Severity
from core.inventory.repository import DeviceRepository
from core.inventory.whitelist import WhitelistRepository
from core.search.repository import SearchRepository
from tests.unit._helpers import migrated_conn

_MAC = "aa:bb:cc:dd:ee:ff"
_MAC2 = "aa:bb:cc:dd:ee:00"


def test_upsert_seen_with_mac(tmp_path):
    conn = migrated_conn(tmp_path)
    try:
        repo = DeviceRepository(conn)
        d = repo.upsert_seen(_MAC, entity_name="kamera",
                             network_type="Hauptnetz")
        assert d.identifier == _MAC
        read = repo.get(_MAC)
        assert read is not None
        assert read.identifier == _MAC
        assert read.entity_name == "kamera"
    finally:
        conn.close()


def test_unknown_device_with_mac(tmp_path):
    rule = UnknownDeviceRule()
    now = datetime.now(UTC)
    event = Event(
        event_id="EVT-2026-09-28-deadbeef",
        timestamp=now,
        source="fritzbox",
        event_type=EventType.DEVICE_PRESENCE.value,
        severity=Severity.INFO,
        data={
            "identifier": _MAC,
            "entity_name": "kamera",
            "network_type": "Hauptnetz",
            "known": False,
        },
    )
    ctx = RuleContext(
        now=now,
        network_id="homelab-default",
        config={"alarm_network": "Hauptnetz"},
    )
    out = rule.evaluate(event, ctx)
    assert len(out) == 1
    assert out[0].event_type == EventType.UNKNOWN_DEVICE.value
    assert out[0].data["identifier"] == _MAC


def test_search_finds_mac_identifier(tmp_path):
    conn = migrated_conn(tmp_path)
    try:
        conn.execute(
            "INSERT INTO devices (identifier, entity_name, "
            "network_type, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            (_MAC, "kamera", "Hauptnetz",
             "2026-09-28T10:00:00+00:00",
             "2026-09-28T10:00:00+00:00"),
        )
        conn.commit()
        repo = SearchRepository(conn)
        hits = repo.search_devices(_MAC)
        assert len(hits) >= 1
        assert hits[0]["identifier"] == _MAC
    finally:
        conn.close()


def test_whitelist_check_with_mac(tmp_path):
    conn = migrated_conn(tmp_path)
    try:
        wl = WhitelistRepository(conn)
        wl.add(_MAC, "kamera")
        conn.commit()
        ids = wl.identifiers()
        assert _MAC in ids
        assert _MAC2 not in ids
    finally:
        conn.close()
