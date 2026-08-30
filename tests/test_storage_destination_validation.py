"""Runtime storage-destination schema revalidation tests."""

from __future__ import annotations

import json

import pytest

from fixture_paths import fixture_path, has_fixture_pcaps
from bdo_toolkit import EventFilter, replay_pcap
from bdo_toolkit._protocol import FlowKey
from bdo_toolkit._storage_destination_validation import (
    _MAX_COHORTS,
    _MAX_WRAPPERS_PER_COHORT,
    StorageDestinationValidator,
)
from bdo_toolkit.calibration import collect_frames_pcap
from bdo_toolkit.capture import _EventCollector


requires_fixtures = pytest.mark.skipif(
    not has_fixture_pcaps(),
    reason="local pcap fixtures not present (private captures)",
)

_AUGUST_STORAGE_OPCODE = 0x1C51
_AUGUST_ITEM_OFFSET = 44
_AUGUST_DESTINATION_OFFSET = 8
_VALIDATION_FLOW = FlowKey("203.0.113.10", 51000, "198.51.100.20", 8889)


def _storage_frames(fixture_name: str):
    return (
        frame
        for frame in collect_frames_pcap(fixture_path(fixture_name))
        if frame.opcode == _AUGUST_STORAGE_OPCODE
    )


def _august_storage_message(storage_id: int, item_id: int) -> bytes:
    message = bytearray(270)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = _AUGUST_STORAGE_OPCODE.to_bytes(2, "little")
    message[5:7] = (1).to_bytes(2, "little")
    message[8:12] = storage_id.to_bytes(4, "little")
    message[44:48] = item_id.to_bytes(4, "little")
    message[48:52] = (1).to_bytes(4, "little")
    message[79:87] = bytes.fromhex("1122334455667788")
    return bytes(message)


def _write_august_storage_profile(tmp_path, *, context_offset: int):
    profile = tmp_path / f"storage-context-{context_offset}.json"
    profile.write_text(
        json.dumps(
            {
                "version": 1,
                "profile_active": True,
                "specs": {
                    "STORAGE_ITEM_DELTA": [
                        {
                            "event": "STORAGE_ITEM_DELTA",
                            "opcode": "0x1C51",
                            "length": 270,
                            "item_id_offset": 44,
                            "quantity_added_offset": 48,
                            "destination_instance_offset": 79,
                            "context_offset": context_offset,
                            "record_count_offset": 5,
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    return profile


@requires_fixtures
def test_stale_plus_one_context_offset_is_proven_across_hydration():
    """A 0x05xx suffix can look like Velia but cannot mimic town diversity."""

    validator = StorageDestinationValidator()
    mismatches = []
    saw_suffix_collision = False
    for frame in _storage_frames("character-switch-2026-08-07.pcapng"):
        saw_suffix_collision |= (
            int.from_bytes(frame.message[8:12], "little") != 5
            and int.from_bytes(frame.message[9:13], "little") == 5
        )
        mismatch = validator.observe(
            flow=frame.context.flow,
            flow_generation=frame.context.flow_generation,
            opcode=frame.opcode,
            message=frame.message,
            first_item_offset=_AUGUST_ITEM_OFFSET,
            configured_offset=_AUGUST_DESTINATION_OFFSET + 1,
        )
        if mismatch is not None:
            mismatches.append(mismatch)

    assert saw_suffix_collision
    assert len(mismatches) == 1
    mismatch = mismatches[0]
    assert mismatch.configured_offset == 9
    assert mismatch.observed_offset == 8
    assert mismatch.wrapper_count >= 4
    assert mismatch.distinct_destinations >= 3


def test_same_opcode_layouts_do_not_share_destination_evidence():
    """A second valid layout must not inherit the first layout's column."""

    validator = StorageDestinationValidator()
    flow = FlowKey("203.0.113.10", 51000, "198.51.100.20", 8889)
    opcode = 0x1234

    for index, storage_id in enumerate((0x0005, 0x0020, 0x0034, 0x004D)):
        message = bytearray(100)
        message[8:12] = storage_id.to_bytes(4, "little")
        message[44:48] = (7000 + index).to_bytes(4, "little")
        assert (
            validator.observe(
                flow=flow,
                flow_generation=1,
                opcode=opcode,
                message=bytes(message),
                first_item_offset=44,
                configured_offset=8,
            )
            is None
        )

    # Layout B legitimately reads byte 27. Its prefix also happens to contain
    # a registered-looking value at byte 8. Before layout identity was part of
    # the cohort key, the four layout-A wrappers made that decoy look proven
    # and falsely diagnosed layout B as stale.
    second_layout = bytearray(100)
    second_layout[8:12] = (0x0005).to_bytes(4, "little")
    second_layout[27:31] = (0x00CA).to_bytes(4, "little")
    second_layout[36:40] = (8000).to_bytes(4, "little")
    assert (
        validator.observe(
            flow=flow,
            flow_generation=1,
            opcode=opcode,
            message=bytes(second_layout),
            first_item_offset=36,
            configured_offset=27,
        )
        is None
    )


def test_repeated_ambiguous_single_town_activity_does_not_guess():
    validator = StorageDestinationValidator()

    for nonce in range(32):
        message = _august_storage_message(0x055F, 7100 + nonce)
        assert (
            validator.observe(
                flow=_VALIDATION_FLOW,
                flow_generation=1,
                opcode=_AUGUST_STORAGE_OPCODE,
                message=message,
                first_item_offset=_AUGUST_ITEM_OFFSET,
                configured_offset=_AUGUST_DESTINATION_OFFSET + 1,
            )
            is None
        )


def test_duplicate_wrappers_and_flow_generations_do_not_combine_into_proof():
    validator = StorageDestinationValidator()
    messages = tuple(
        _august_storage_message(storage_id, 7100 + index)
        for index, storage_id in enumerate((0x055F, 0x0566, 0x058C))
    )

    for generation, message in enumerate(messages):
        # Two callbacks for one wrapper remain one piece of evidence.  Keeping
        # each wrapper in another TCP generation also prevents cross-connection
        # accumulation from reaching the four-wrapper proof threshold.
        for _ in range(2):
            assert (
                validator.observe(
                    flow=_VALIDATION_FLOW,
                    flow_generation=generation,
                    opcode=_AUGUST_STORAGE_OPCODE,
                    message=message,
                    first_item_offset=_AUGUST_ITEM_OFFSET,
                    configured_offset=_AUGUST_DESTINATION_OFFSET + 1,
                )
                is None
            )

    assert validator.cohort_count == 3
    assert validator.retained_wrapper_count == 3

    validator.close_flow(_VALIDATION_FLOW)
    assert validator.cohort_count == 0
    assert validator.retained_wrapper_count == 0


def test_destination_revalidation_state_is_bounded():
    validator = StorageDestinationValidator()

    for nonce in range(_MAX_WRAPPERS_PER_COHORT + 17):
        message = _august_storage_message(0x055F, 7100 + nonce)
        validator.observe(
            flow=_VALIDATION_FLOW,
            flow_generation=1,
            opcode=_AUGUST_STORAGE_OPCODE,
            message=message,
            first_item_offset=_AUGUST_ITEM_OFFSET,
            configured_offset=_AUGUST_DESTINATION_OFFSET,
        )

    assert validator.cohort_count == 1
    assert validator.retained_wrapper_count == _MAX_WRAPPERS_PER_COHORT

    for port in range(_MAX_COHORTS + 9):
        validator.observe(
            flow=FlowKey("1.1.1.1", port, "2.2.2.2", 8889),
            flow_generation=port,
            opcode=_AUGUST_STORAGE_OPCODE,
            message=_august_storage_message(0x055F, 9000 + port),
            first_item_offset=_AUGUST_ITEM_OFFSET,
            configured_offset=_AUGUST_DESTINATION_OFFSET,
        )

    assert validator.cohort_count == _MAX_COHORTS
    assert validator.retained_wrapper_count <= (
        _MAX_COHORTS * _MAX_WRAPPERS_PER_COHORT
    )


def test_collector_marks_incompatible_when_known_suffix_collision_is_disproved(
    tmp_path,
):
    diagnostics = []
    collector = _EventCollector(
        server_ports=(8889,),
        opcode_profile=_write_august_storage_profile(
            tmp_path,
            context_offset=_AUGUST_DESTINATION_OFFSET + 1,
        ),
        event_filter=EventFilter.all(),
        on_diagnostic=diagnostics.append,
    )
    payload = b"".join(
        _august_storage_message(storage_id, 7000 + index)
        for index, storage_id in enumerate((0x055F, 0x0566, 0x058C, 0x0590))
    )
    collector.engine.process_tcp_segment(
        source_ip="203.0.113.10",
        source_port=8889,
        destination_ip="198.51.100.20",
        destination_port=51000,
        sequence=1000,
        payload=payload,
        timestamp=1000.0,
    )
    collector.engine.finish()
    collector.finalize()

    mismatches = [
        diagnostic
        for diagnostic in diagnostics
        if diagnostic.code == "storage_destination_schema_mismatch"
    ]
    events = list(collector.drain_events())
    assert len(events) == 4
    assert {event.storage_id for event in events} == {5}
    assert {event.storage_name for event in events} == {"Velia"}
    assert len(mismatches) == 1
    assert "active profile uses byte 9" in mismatches[0].message
    assert "Events were not relabeled" in mismatches[0].message
    assert collector.decoder_health.storage_status == "incompatible"
    assert collector.decoder_health.storage_destination_failures == 0


@requires_fixtures
@pytest.mark.parametrize(
    "fixture_name",
    (
        "character-switch-2026-08-07.pcapng",
        "velia_7003_qty5.pcapng",
    ),
)
def test_correct_profile_replay_emits_no_schema_mismatch(fixture_name):
    diagnostics = []

    events = list(
        replay_pcap(
            fixture_path(fixture_name),
            opcode_profile=fixture_path(
                "character-switch-2026-08-07.profile.json"
            ),
            event_filter=EventFilter.all(),
            on_diagnostic=diagnostics.append,
        )
    )

    assert events
    assert all(
        diagnostic.code != "storage_destination_schema_mismatch"
        for diagnostic in diagnostics
    )
