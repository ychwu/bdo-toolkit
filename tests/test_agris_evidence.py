"""Optional private evidence: raw pre-patch grind, not post-patch JSON reports.

Post-patch geometry is covered synthetically until an independently replayable
raw capture is available. No item opcode profile participates in this replay.
"""

import json

import pytest

from bdo_toolkit.agris.replay import replay_agris
from fixture_paths import optional_fixture_path


GRIND = optional_fixture_path("research--agris-grind-98600-to-96720--e5d398bcd7")


@pytest.mark.skipif(not GRIND.is_file(), reason="private Agris grind capture is not installed")
def test_raw_grind_discovers_and_emits_latest_balances_without_startup_history():
    with replay_agris(GRIND, expected_maximum_points=100000) as replay:
        observations = list(replay)
        status = replay.status
        health = replay.health

    assert status.status == "tracking"
    assert status.balance is not None
    assert status.balance.remaining_points == 96720
    assert status.balance.maximum_points == 100000
    assert status.balance.confidence == "inferred"
    assert status.observed_frames == 2521
    assert len(status.candidates) == 1
    layout = status.candidates[0]
    assert (layout.opcode, layout.message_length, layout.remaining_offset, layout.maximum_offset) == (
        0x1337, 40, 9, 13,
    )

    # The capture contains 45 balance messages, starting at 98560. Learning
    # withholds those early records instead of retrospectively emitting them.
    assert len(observations) == 41
    assert observations[0].remaining_points == 98360
    assert observations[-1] == status.balance
    assert all(event.maximum_points == 100000 for event in observations)
    assert all(event.remaining_points != 98560 for event in observations)
    assert health.packets_processed == 65524
    assert health.capture_is_clean
    assert health.tcp_gap_resets == 0
    assert health.pcap_dropped is None  # Offline counters are unavailable.

    serialized = json.dumps([status.to_dict(), *[event.to_dict() for event in observations]])
    for forbidden in ("starting", "consumed", "consumption", "delta", "kill_count"):
        assert forbidden not in serialized
