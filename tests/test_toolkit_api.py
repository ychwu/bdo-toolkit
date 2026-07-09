"""Public API tests ported from the legacy repo's toolkit test suite."""

import pytest

from fixture_paths import fixture_path, has_fixture_pcaps
from bdo_toolkit import load_opcode_profile, replay_pcap

requires_fixtures = pytest.mark.skipif(
    not has_fixture_pcaps(),
    reason="local pcap fixtures not present (private captures)",
)


def test_default_profile_loads_from_package_data():
    profile = load_opcode_profile()

    assert profile.active
    assert "INVENTORY_TRANSFER" in profile.specs
    assert "STORAGE_ITEM_DELTA" in profile.specs


@requires_fixtures
def test_replay_batch_storage_deposit_as_structured_events():
    events = list(
        replay_pcap(fixture_path("5960_qty1_and_4015_qty1_multi.pcapng"))
    )

    assert len(events) == 2
    assert [event.event_type for event in events] == ["storage_delta", "storage_delta"]
    assert [event.source for event in events] == [
        "Batch Storage Deposit",
        "Batch Storage Deposit",
    ]
    assert [event.item_id for event in events] == [5960, 4015]
    assert [event.quantity for event in events] == [1, 1]
    assert [event.record_index for event in events] == [1, 2]
    assert [event.record_count for event in events] == [2, 2]
    assert [event.storage_instance for event in events] == [
        "0xb6391c5dcc1b8e00",
        "0xbf8d491bcc1b8e00",
    ]


@requires_fixtures
def test_replay_filters_by_event_type_and_source():
    fixture = fixture_path("5960_qty1_and_4015_qty1_multi.pcapng")

    assert list(replay_pcap(fixture, event_types={"item_received"})) == []
    worker_events = list(replay_pcap(fixture, sources={"Batch Storage Deposit"}))
    assert len(worker_events) == 2
    assert list(replay_pcap(fixture, item_ids={5960}))[0].item_id == 5960


@requires_fixtures
def test_manual_bulk_deposit_uses_batch_storage_label_not_worker():
    events = list(
        replay_pcap(fixture_path("1000306_qty5_unstackable_i2s.pcapng"))
    )

    assert len(events) == 5
    assert {event.source for event in events} == {"Batch Storage Deposit"}
    assert [event.record_index for event in events] == [1, 2, 3, 4, 5]


@requires_fixtures
def test_event_to_dict_round_trips_extra_fields():
    fixture = fixture_path("5960_qty1_and_4015_qty1_multi.pcapng")
    event = next(iter(replay_pcap(fixture)))
    data = event.to_dict()

    assert data["event_type"] == "storage_delta"
    assert data["extra"]["storage_delta"] == event.quantity
    assert "stream_sequence" in data["extra"]

