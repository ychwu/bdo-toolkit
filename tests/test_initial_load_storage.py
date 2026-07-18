import json
from collections import Counter

import pytest

from bdo_toolkit import EventFilter, replay_pcap
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

