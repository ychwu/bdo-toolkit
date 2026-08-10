import json
from collections import Counter

import pytest

from bdo_toolkit import EventFilter, replay_pcap
from bdo_toolkit.item_state import analyze_item_state_pcap
from fixture_paths import fixture_path, has_fixture_pcaps


requires_fixtures = pytest.mark.skipif(
    not has_fixture_pcaps(), reason="private packet fixtures are not available"
)


@requires_fixtures
def test_initial_game_load_is_separated_from_live_storage_activity(tmp_path):
    """The July 17 startup capture is hydration, not a character switch."""
    try:
        capture = fixture_path("fullcapture.pcapng")
    except FileNotFoundError:
        pytest.skip("July 17 private initial-load fixture not present")

    profile = tmp_path / "opcodes.local"
    profile.write_text(
        json.dumps(
            {
                "version": 1,
                "profile_active": True,
                "specs": {
                    "STORAGE_ITEM_DELTA": [
                        {
                            "event": "STORAGE_ITEM_DELTA",
                            "opcode": "0x126D",
                            "length": 257,
                            "item_id_offset": 36,
                            "quantity_added_offset": 40,
                            "destination_instance_offset": 71,
                            "context_offset": 27,
                            "record_count_offset": 16,
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    events = list(replay_pcap(capture, opcode_profile=profile))
    counts = Counter(event.event_type for event in events)

    # The capture contains two complete server hydrations of the same 32-town
    # storage state, followed by genuine live worker deposits.  Hydration must
    # never masquerade as a deposit or enter origin classification.
    assert counts == {"storage_snapshot": 2480, "storage_delta": 245}

    snapshots = [event for event in events if event.event_type == "storage_snapshot"]
    live = [event for event in events if event.event_type == "storage_delta"]

    assert all(event.storage_operation == "snapshot" for event in snapshots)
    assert all(event.deposit_origin is None for event in snapshots)
    assert all("storage_delta" not in event.extra for event in snapshots)
    assert all("storage_quantity" in event.extra for event in snapshots)

    assert all(event.storage_operation == "live" for event in live)
    assert all(event.deposit_origin == "worker" for event in live)
    assert all("storage_delta" in event.extra for event in live)

    # Arehaza has 25 occupied slots per hydration.  The first three records do
    # not carry the old FF marker, so this also locks count/length stride
    # derivation rather than marker-only recovery.
    arehaza = [event for event in snapshots if event.storage_id == 0x02B5]
    assert len(arehaza) == 50
    assert {11, 13, 14}.issubset(event.item_id for event in arehaza)

    named_nonempty_storages = {
        event.storage_id
        for event in snapshots
        if event.storage_id is not None and event.storage_name is not None
    }
    assert len(named_nonempty_storages) == 29

    live_filter = EventFilter(event_types={"item_received", "storage_delta"})
    assert sum(live_filter.allows(event) for event in events) == 245


def _august7_profile(tmp_path):
    profile = tmp_path / "opcodes-2026-08-07.json"
    profile.write_text(
        json.dumps(
            {
                "version": 1,
                "profile_active": True,
                "specs": {
                    "INVENTORY_TRANSFER": [
                        {
                            "event": "INVENTORY_TRANSFER",
                            "opcode": "0x1424",
                            "length": 255,
                            "item_id_offset": 34,
                            "quantity_offset": 38,
                            "item_instance_offset": 69,
                            "context_offset": 21,
                        }
                    ],
                    "STORAGE_ITEM_DELTA": [
                        {
                            "event": "STORAGE_ITEM_DELTA",
                            "opcode": "0x1C51",
                            "length": 270,
                            "item_id_offset": 44,
                            "quantity_added_offset": 48,
                            "destination_instance_offset": 79,
                            "context_offset": 8,
                            "record_count_offset": 5,
                        }
                    ],
                    "SOURCE_STACK_DECREMENT": [
                        {
                            "event": "SOURCE_STACK_DECREMENT",
                            "opcode": "0x1505",
                            "length": 47,
                            "quantity_removed_offset": 26,
                            "source_instance_offset": 39,
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    return profile


@requires_fixtures
def test_august_character_switch_hydration_is_not_live_activity(tmp_path):
    try:
        capture = fixture_path("character-switch-2026-08-07.pcapng")
    except FileNotFoundError:
        pytest.skip("August 7 private character-switch fixture not present")
    profile = _august7_profile(tmp_path)

    events = list(replay_pcap(capture, opcode_profile=profile))
    counts = Counter(event.event_type for event in events)

    assert counts == {"inventory_snapshot": 78, "storage_snapshot": 2452}
    assert not any(EventFilter.activity().allows(event) for event in events)
    assert {event.storage_id for event in events if event.event_type == "storage_snapshot"} >= {
        0x0005,
        0x0020,
        0x02B5,
    }

    state = analyze_item_state_pcap(capture, opcode_profile=profile)
    assert state.inventory.serialized_records == 78
    assert state.inventory.currency_balance_records == 4
    assert state.inventory.unclassified_records == 0
    assert state.storage_snapshot_records == 2452
    assert len(state.storages) == 33
    assert state.empty_storage_destinations == 4
    assert state.storage_named("Arehaza").occupied_stacks == 25


@requires_fixtures
def test_august_controlled_deposit_keeps_town_and_opcode_free_worker_origin(tmp_path):
    try:
        capture = fixture_path("velia_7003_qty5.pcapng")
    except FileNotFoundError:
        pytest.skip("August 7 private controlled-deposit fixture not present")
    profile = _august7_profile(tmp_path)

    events = list(replay_pcap(capture, opcode_profile=profile))

    assert [
        (event.item_id, event.quantity, event.source, event.deposit_origin)
        for event in events
    ] == [
        (7003, 5, "Velia", "manual"),
        (4003, 20, "Heidel", "worker"),
        (7702, 31, "Velia", "worker"),
    ]
    workers = [event for event in events if event.deposit_origin == "worker"]
    assert all(
        event.extra["deposit_origin_evidence"]["companion_chain"]["known_family"]
        is False
        for event in workers
    )
    assert all(
        event.extra["deposit_origin_evidence"]["companion_chain"][
            "confirmed_family"
        ]
        is True
        for event in workers
    )
