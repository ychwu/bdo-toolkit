"""Deposit-origin classification: worker vs manual vs unknown.

Fixture tests lock the classifier to the labeled captures (including the
7002 ambient non-matching decrement and both storage-delta context modes);
synthetic tests pin the fail-closed rules that no capture currently
exercises.
"""

from dataclasses import replace
import json
from pathlib import Path
from threading import Event as ThreadEvent, RLock, Thread

import pytest

from fixture_paths import (
    JULY6_OPCODE_PROFILE,
    JULY17_OPCODE_PROFILE,
    fixture_path,
    has_fixture_pcaps,
)
from bdo_toolkit import EventFilter, replay_pcap
from bdo_toolkit.capture import _EventCollector, _decrement_specs
from bdo_toolkit._deposit_origin import DecrementSpec, DepositOriginTracker
from bdo_toolkit._engine import PacketEngine, toolkit_event_from_record
from bdo_toolkit._protocol import BDOFrame, EventSpec, FlowKey, PacketContext
from bdo_toolkit.events import BDOEvent, Flow
from bdo_toolkit.profiles import OpcodeProfile, ProfileError
from bdo_toolkit.origin_learning import discover_companion_observation

requires_fixtures = pytest.mark.skipif(
    not has_fixture_pcaps(),
    reason="local pcap fixtures not present (private captures)",
)


def test_closed_flow_histories_are_released_across_long_sessions():
    tracker = DepositOriginTracker(decrement_specs=(), emit=lambda event: None)
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(),
        on_event=lambda event, raw: None,
        frame_observer=tracker.observe_frame,
        stream_observer=tracker.observe_stream,
        flow_close_observer=tracker.close_flow,
    )
    generic_frame = b"\x05\x00\x00\x34\x12"

    for index in range(1000):
        engine.process_tcp_segment(
            source_ip="10.0.0.1",
            source_port=8889,
            destination_ip="10.0.0.2",
            destination_port=40000 + index,
            sequence=1000,
            payload=generic_frame,
            timestamp=float(index),
            fin=True,
        )

    assert tracker._recent == {}
    assert tracker._stream_spans == {}
    assert tracker._first_record_boundaries == {}
    assert tracker._observed_chains == set()

# Worker deposits span BOTH storage-delta context modes (05 and 20).
WORKER_FIXTURES = [
    "worker_4607.pcapng",
    "5960_qty1_and_4015_qty1_multi.pcapng",
    "7360_hit2_qty10.pcapng",
    "7002_qty25.pcapng",
]
MANUAL_FIXTURES = [
    "1000306_qty5_unstackable_i2s.pcapng",
    "new_potato_3_tostorage.pcapng",
    "new_potato_1_1_1.pcapng",
]


def _classified_sources(fixture):
    return [
        (event.source, event.extra.get("deposit_origin_evidence"))
        for event in replay_pcap(
            fixture_path(fixture),
            opcode_profile=JULY6_OPCODE_PROFILE,
        )
        if event.event_type == "storage_delta"
    ]


@requires_fixtures
@pytest.mark.parametrize("fixture", WORKER_FIXTURES)
def test_worker_deposits_classify_as_worker(fixture):
    results = _classified_sources(fixture)
    assert results, f"no storage_delta events decoded from {fixture}"
    for source, evidence in results:
        assert source == "Worker Production"
        assert evidence["worker_companions"] is True
        assert evidence["matching_decrement"] is False
        chain = evidence["companion_chain"]
        assert chain["detection"] == "shared-token-chain-v1"
        assert chain["known_family"] is False


@requires_fixtures
@pytest.mark.parametrize("fixture", MANUAL_FIXTURES)
def test_manual_deposits_classify_as_manual(fixture):
    results = _classified_sources(fixture)
    assert results, f"no storage_delta events decoded from {fixture}"
    for source, evidence in results:
        assert source == "Player Inventory"
        assert evidence["worker_companions"] is False
        assert evidence["matching_decrement"] is True
        assert evidence["manual_decrement"]["confidence"] in {
            "observed",
            "structural",
        }
        assert evidence["manual_decrement"]["source_instance_offset"] >= 0


@requires_fixtures
def test_legacy_manual_fixtures_distinguish_identity_confidence_and_stride():
    full_stack = _classified_sources("new_potato_3_tostorage.pcapng")
    partial_stack = _classified_sources("new_potato_1_1_1.pcapng")
    unstackable_batch = _classified_sources(
        "1000306_qty5_unstackable_i2s.pcapng"
    )

    assert len(full_stack) == 1
    full_evidence = full_stack[0][1]["manual_decrement"]
    assert full_evidence["confidence"] == "observed"
    assert full_evidence["instance_matches_destination"] is True

    # A genuine partial-stack manual move receives a new destination
    # identity. Its calibrated source field is still anchored evidence, but
    # it must not claim the exact-match confidence used above.
    assert len(partial_stack) == 1
    partial_evidence = partial_stack[0][1]["manual_decrement"]
    assert partial_evidence["confidence"] == "structural"
    assert partial_evidence["instance_matches_destination"] is False

    # The historical profile predates repeat_stride. The matching code safely
    # infers its capture-proven 23-byte geometry from the five-record storage
    # batch, then requires exact identity for each inferred nonzero offset.
    assert len(unstackable_batch) == 5
    batch_evidence = [
        evidence["manual_decrement"] for _, evidence in unstackable_batch
    ]
    assert [entry["quantity_offset"] for entry in batch_evidence] == [
        42,
        65,
        88,
        111,
        134,
    ]
    assert [entry["source_instance_offset"] for entry in batch_evidence] == [
        34,
        57,
        80,
        103,
        126,
    ]
    assert all(entry["confidence"] == "observed" for entry in batch_evidence)
    assert all(
        entry["instance_matches_destination"] is True
        for entry in batch_evidence
    )


# --- synthetic fail-closed behavior ---

FLOW = FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000)


def _frame(opcode, seq, timestamp=1000.0, body=b"", length=None):
    payload = bytearray(max(length or (5 + len(body)), 5 + len(body)))
    payload[0:2] = len(payload).to_bytes(2, "little")
    payload[3:5] = opcode.to_bytes(2, "little")
    payload[5 : 5 + len(body)] = body
    return BDOFrame(
        index=0,
        message=bytes(payload),
        context=PacketContext(timestamp=timestamp, flow=FLOW),
        stream_sequence=seq,
    )


def _storage_event(
    item_id=7002,
    quantity=25,
    seq=1000,
    timestamp=1000.0,
    message_length=5,
    record_offset=37,
    storage_instance=None,
):
    return BDOEvent(
        event_type="storage_delta",
        timestamp=timestamp,
        flow=Flow("10.0.0.1", 8889, "10.0.0.2", 50000),
        item_id=item_id,
        quantity=quantity,
        opcode=0x0E6A,
        message_length=message_length,
        record_offset=record_offset,
        storage_instance=storage_instance,
        extra={"stream_sequence": seq},
    )


def _worker_chain(
    delta_seq=1000,
    delta_opcode=0x0E6A,
    first=0x1558,
    second=0x1168,
    token=bytes.fromhex("07feabbfc91b8e00"),
):
    delta = bytearray(80)
    delta[0:2] = (80).to_bytes(2, "little")
    delta[3:5] = delta_opcode.to_bytes(2, "little")
    delta[18:26] = token
    first_message = bytearray(58)
    first_message[0:2] = (58).to_bytes(2, "little")
    first_message[3:5] = first.to_bytes(2, "little")
    first_message[36:44] = token
    second_message = bytearray(23)
    second_message[0:2] = (23).to_bytes(2, "little")
    second_message[3:5] = second.to_bytes(2, "little")
    second_message[5:13] = token
    return (
        BDOFrame(0, bytes(delta), PacketContext(1000.0, FLOW), delta_seq),
        BDOFrame(1, bytes(first_message), PacketContext(1000.0, FLOW), delta_seq + 80),
        BDOFrame(2, bytes(second_message), PacketContext(1000.0, FLOW), delta_seq + 138),
    )


def _tracker(emitted):
    return DepositOriginTracker(
        decrement_specs=(DecrementSpec(0x1A32, 52, 42),),
        emit=emitted.append,
    )


def test_discovery_reuses_negative_matches_but_rechecks_overlapping_bytes(monkeypatch):
    calls = []

    def counted_discovery(**kwargs):
        calls.append(None)
        return discover_companion_observation(**kwargs)

    monkeypatch.setattr(
        "bdo_toolkit._deposit_origin.discover_companion_observation",
        counted_discovery,
    )
    emitted = []
    tracker = _tracker(emitted)
    delta, first, second = _worker_chain()
    tracker.observe_frame(delta)
    tracker.register(_storage_event(message_length=80))
    missing_token = bytearray(first.message)
    missing_token[36:44] = b"\x00" * 8
    context = PacketContext(1000.0, FLOW, stream_start=1080)
    payload = bytes(missing_token) + second.message
    tracker.observe_stream(payload, context)
    assert len(calls) == 1
    for _ in range(10):
        tracker.observe_stream(payload, context)
    assert len(calls) == 1
    assert emitted == []

    # The newest overlapping bytes now supply a real chain. A sequence-only
    # cache would incorrectly keep the earlier negative result.
    tracker.observe_stream(first.message, context)
    assert len(calls) == 2
    assert [event.source for event in emitted] == ["Worker Production"]


@pytest.mark.parametrize("reused_token", [False, True])
@pytest.mark.parametrize("entry_limit, byte_limit", [
    (0, 0), (4096, 64), (1, 2 * 1024 * 1024), (4096, 180),
    (4096, 2 * 1024 * 1024),
])
def test_discovery_cache_pressure_preserves_late_storage_ownership(
    reused_token, entry_limit, byte_limit,
):
    emitted = []
    tracker = _tracker(emitted)
    tracker.COMPANION_DISCOVERY_CACHE_LIMIT = entry_limit
    tracker.COMPANION_DISCOVERY_CACHE_BYTES = byte_limit
    delta_a, first, second = _worker_chain()
    token_b = (
        delta_a.message[18:26] if reused_token
        else bytes.fromhex("3141592653589793")
    )
    delta_b, _, _ = _worker_chain(delta_seq=1080, token=token_b)
    # Raw bytes arrive before target registration supplies the crossed
    # wrapper's first-record boundary. Positive discovery must remain provisional.
    tracker.observe_stream(
        delta_a.message + delta_b.message + first.message + second.message,
        PacketContext(1000.0, FLOW, stream_start=1000),
    )
    tracker.register(_storage_event(message_length=80), raw_message=delta_a.message)
    assert tracker._pending[0].awaiting_storage_boundaries == frozenset({1080})
    assert emitted == []
    tracker.register(
        _storage_event(item_id=7003, seq=1080, message_length=80),
        raw_message=delta_b.message,
    )
    assert len(tracker._companion_discoveries) <= entry_limit
    assert tracker._companion_discovery_bytes <= byte_limit
    assert tracker._companion_discovery_bytes == sum(
        size for _observation, size in tracker._companion_discoveries.values()
    )
    tracker.finalize_all()
    assert {event.item_id: event.source for event in emitted} == {
        7002: None if reused_token else "Worker Production",
        7003: None,
    }
    assert tracker._companion_discoveries == {}
    assert tracker._companion_discovery_bytes == 0


def test_cached_discovery_preserves_independent_operation_and_flow_identity(monkeypatch):
    calls = []

    def counted_discovery(**kwargs):
        calls.append(None)
        return discover_companion_observation(**kwargs)

    monkeypatch.setattr(
        "bdo_toolkit._deposit_origin.discover_companion_observation",
        counted_discovery,
    )
    emitted = []
    observations = []
    tracker = DepositOriginTracker(
        decrement_specs=(), emit=emitted.append, origin_observer=observations.append,
    )
    other_flow = FlowKey("10.0.0.3", 8889, "10.0.0.4", 50001)
    identities = [(FLOW, 1000, 1000.0), (FLOW, 2000, 1000.1), (other_flow, 3000, 1000.2)]
    for flow, sequence, timestamp in identities:
        delta, first, second = _worker_chain(delta_seq=sequence)
        context = PacketContext(timestamp, flow)
        tracker.observe_frame(replace(delta, context=context))
        event = replace(
            _storage_event(seq=sequence, timestamp=timestamp, message_length=80),
            flow=Flow(
                flow.source_ip, flow.source_port,
                flow.destination_ip, flow.destination_port,
            ),
        )
        tracker.register(event, raw_message=delta.message)
        tracker.observe_frame(replace(first, context=context))
        tracker.observe_frame(replace(second, context=context))
    assert len(calls) == 1
    assert [(o.flow, o.stream_sequence, o.timestamp) for o in observations] == identities
    assert len({o.observation_id for o in observations}) == 3
    assert [event.source for event in emitted] == ["Worker Production"] * 3
    assert tracker._companion_discoveries
    tracker.close_flow(other_flow)
    assert tracker._companion_discoveries == {}
    assert tracker._companion_discovery_bytes == 0


def test_discovery_cache_key_preserves_prefix_boundary_and_frame_validation():
    tracker = _tracker([])
    delta, first, second = _worker_chain()
    tracker.register(_storage_event(message_length=80), raw_message=delta.message)
    pending = tracker._pending[0]
    for message, boundary in (
        (delta.message, 37),
        (delta.message, 20),  # Cuts the token, even with otherwise identical bytes.
        (delta.message[:-1], 37),  # Same prefix but inconsistent declared length.
        (delta.message, 37),
    ):
        actual = tracker._discover_companions(
            pending, message, first.message, second.message, boundary,
        )
        expected = discover_companion_observation(
            delta_message=message, first_message=first.message,
            second_message=second.message, timestamp=1000.0, flow=FLOW,
            stream_sequence=1000, delta_prefix_end=boundary,
        )
        assert actual == expected


def _instance_manual_tracker(emitted):
    return DepositOriginTracker(
        decrement_specs=(
            DecrementSpec(
                0x11AD,
                47,
                27,
                source_instance_offset=35,
            ),
        ),
        emit=emitted.append,
    )


def _manual_decrement_frame(
    *,
    seq,
    quantity,
    source_instance,
    timestamp=999.0,
    flow_generation=0,
):
    message = bytearray(47)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x11AD).to_bytes(2, "little")
    message[27:31] = quantity.to_bytes(4, "little")
    message[35:43] = source_instance
    return BDOFrame(
        0,
        bytes(message),
        PacketContext(
            timestamp,
            FLOW,
            flow_generation=flow_generation,
        ),
        seq,
    )


def test_manual_decrement_requires_calibrated_length_and_offset():
    emitted = []
    tracker = _tracker(emitted)
    wrong_length = bytearray(45)
    wrong_length[0:2] = (45).to_bytes(2, "little")
    wrong_length[3:5] = (0x1A32).to_bytes(2, "little")
    wrong_length[38:42] = (3).to_bytes(4, "little")
    tracker.observe_frame(
        BDOFrame(0, bytes(wrong_length), PacketContext(999.0, FLOW), 900)
    )
    tracker.observe_frame(_frame(0x0E6A, seq=1000))
    tracker.register(_storage_event(quantity=3, seq=1000))
    tracker.finalize_all()

    assert emitted[0].source is None
    assert emitted[0].extra["deposit_origin_evidence"]["matching_decrement"] is False


def test_common_quantity_does_not_match_an_empty_declared_instance_field():
    emitted = []
    tracker = DepositOriginTracker(
        decrement_specs=(
            DecrementSpec(
                0x11AD,
                47,
                27,
                source_instance_offset=35,
            ),
        ),
        emit=emitted.append,
    )
    decrement = bytearray(47)
    decrement[0:2] = len(decrement).to_bytes(2, "little")
    decrement[3:5] = (0x11AD).to_bytes(2, "little")
    decrement[27:31] = (1).to_bytes(4, "little")
    # source_instance@35 remains zero: this is a coincidental quantity, not
    # a structurally valid calibrated decrement record.
    tracker.observe_frame(
        BDOFrame(0, bytes(decrement), PacketContext(999.0, FLOW), 900)
    )
    tracker.observe_frame(_frame(0x0E6A, seq=1000))
    tracker.register(
        _storage_event(
            quantity=1,
            seq=1000,
            storage_instance="0x1122334455667788",
        )
    )
    tracker.finalize_all()

    assert emitted[0].source is None
    assert emitted[0].extra["deposit_origin_evidence"]["matching_decrement"] is False


def test_exact_instance_match_accepts_low_entropy_identity():
    emitted = []
    tracker = DepositOriginTracker(
        decrement_specs=(
            DecrementSpec(
                0x11AD,
                47,
                27,
                source_instance_offset=35,
            ),
        ),
        emit=emitted.append,
    )
    instance = bytes.fromhex("0102030400000000")
    decrement = bytearray(47)
    decrement[0:2] = len(decrement).to_bytes(2, "little")
    decrement[3:5] = (0x11AD).to_bytes(2, "little")
    decrement[27:31] = (1).to_bytes(4, "little")
    decrement[35:43] = instance
    tracker.observe_frame(
        BDOFrame(0, bytes(decrement), PacketContext(999.0, FLOW), 900)
    )
    tracker.observe_frame(_frame(0x0E6A, seq=1000))
    tracker.register(
        _storage_event(
            quantity=1,
            seq=1000,
            storage_instance=f"0x{instance.hex()}",
        )
    )
    tracker.finalize_all()

    assert emitted[0].source == "Player Inventory"
    manual = emitted[0].extra["deposit_origin_evidence"]["manual_decrement"]
    assert manual["confidence"] == "observed"
    assert manual["instance_matches_destination"] is True


def test_nonexact_structural_instance_requires_entropy_in_both_halves():
    emitted = []
    tracker = DepositOriginTracker(
        decrement_specs=(
            DecrementSpec(
                0x11AD,
                47,
                27,
                source_instance_offset=35,
            ),
        ),
        emit=emitted.append,
    )
    decrement = bytearray(47)
    decrement[0:2] = len(decrement).to_bytes(2, "little")
    decrement[3:5] = (0x11AD).to_bytes(2, "little")
    decrement[27:31] = (1).to_bytes(4, "little")
    decrement[35:43] = bytes.fromhex("0102030400000000")
    tracker.observe_frame(
        BDOFrame(0, bytes(decrement), PacketContext(999.0, FLOW), 900)
    )
    tracker.observe_frame(_frame(0x0E6A, seq=1000))
    tracker.register(
        _storage_event(
            quantity=1,
            seq=1000,
            storage_instance="0x1122334455667788",
        )
    )
    tracker.finalize_all()

    assert emitted[0].source is None
    assert emitted[0].extra["deposit_origin_evidence"]["matching_decrement"] is False


def test_valid_nonexact_instance_is_explicit_structural_evidence():
    emitted = []
    tracker = DepositOriginTracker(
        decrement_specs=(
            DecrementSpec(
                0x11AD,
                47,
                27,
                source_instance_offset=35,
            ),
        ),
        emit=emitted.append,
    )
    decrement = bytearray(47)
    decrement[0:2] = len(decrement).to_bytes(2, "little")
    decrement[3:5] = (0x11AD).to_bytes(2, "little")
    decrement[27:31] = (1).to_bytes(4, "little")
    decrement[35:43] = bytes.fromhex("1020304050607080")
    tracker.observe_frame(
        BDOFrame(0, bytes(decrement), PacketContext(999.0, FLOW), 900)
    )
    tracker.observe_frame(_frame(0x0E6A, seq=1000))
    tracker.register(
        _storage_event(
            quantity=1,
            seq=1000,
            storage_instance="0x1122334455667788",
        )
    )
    tracker.finalize_all()

    assert emitted[0].source == "Player Inventory"
    manual = emitted[0].extra["deposit_origin_evidence"]["manual_decrement"]
    assert manual["match_kind"] == "anchored-instance-and-quantity"
    assert manual["confidence"] == "structural"
    assert manual["instance_matches_destination"] is False


def test_configured_decrement_stride_matches_the_corresponding_record():
    emitted = []
    tracker = DepositOriginTracker(
        decrement_specs=(
            DecrementSpec(
                0x1A32,
                52,
                42,
                source_instance_offset=34,
                repeat_stride=23,
            ),
        ),
        emit=emitted.append,
    )
    first_instance = bytes.fromhex("1020304050607080")
    second_instance = bytes.fromhex("1122334455667788")
    decrement = bytearray(75)
    decrement[0:2] = len(decrement).to_bytes(2, "little")
    decrement[3:5] = (0x1A32).to_bytes(2, "little")
    decrement[34:42] = first_instance
    decrement[42:46] = (2).to_bytes(4, "little")
    decrement[57:65] = second_instance
    decrement[65:69] = (8).to_bytes(4, "little")
    tracker.observe_frame(
        BDOFrame(0, bytes(decrement), PacketContext(999.0, FLOW), 900)
    )
    tracker.observe_frame(_frame(0x0E6A, seq=1000))
    tracker.register(
        _storage_event(
            quantity=8,
            seq=1000,
            storage_instance=f"0x{second_instance.hex()}",
        )
    )
    tracker.finalize_all()

    assert emitted[0].source == "Player Inventory"
    manual = emitted[0].extra["deposit_origin_evidence"]["manual_decrement"]
    assert manual["quantity_offset"] == 65
    assert manual["source_instance_offset"] == 57
    assert manual["confidence"] == "observed"


@pytest.mark.parametrize("record_count", range(1, 9))
def test_current_decrement_stride_accepts_odd_and_even_batch_counts(record_count):
    emitted = []
    tracker = DepositOriginTracker(
        decrement_specs=(
            DecrementSpec(
                0x1505,
                47,
                26,
                source_instance_offset=39,
                repeat_stride=21,
            ),
        ),
        emit=emitted.append,
    )
    instances = tuple(
        (0x008E1BCCCF2C7101 + index * 0x21).to_bytes(8, "little")
        for index in range(record_count)
    )
    decrement = bytearray(47 + (record_count - 1) * 21)
    decrement[0:2] = len(decrement).to_bytes(2, "little")
    decrement[3:5] = (0x1505).to_bytes(2, "little")
    for index, instance in enumerate(instances):
        delta = index * 21
        decrement[26 + delta : 30 + delta] = (1).to_bytes(4, "little")
        decrement[39 + delta : 47 + delta] = instance

    tracker.observe_frame(
        BDOFrame(0, bytes(decrement), PacketContext(999.0, FLOW), 900)
    )
    message_length = 270 + (record_count - 1) * 228
    storage_sequence = 900 + len(decrement)
    tracker.observe_frame(
        _frame(0x1C51, seq=storage_sequence, length=message_length)
    )
    for index, instance in enumerate(instances, start=1):
        tracker.register(
            replace(
                _storage_event(
                    item_id=15156,
                    quantity=1,
                    seq=storage_sequence,
                    message_length=message_length,
                    record_offset=44 + (index - 1) * 228,
                    storage_instance=f"0x{instance.hex()}",
                ),
                event_type="storage_record",
                opcode=0x1C51,
                record_index=index,
                record_count=record_count,
            )
        )
    tracker.finalize_all()

    assert len(emitted) == record_count
    assert all(event.event_type == "storage_delta" for event in emitted)
    assert all(event.source == "Player Inventory" for event in emitted)
    assert [
        event.extra["deposit_origin_evidence"]["manual_decrement"][
            "record_index"
        ]
        for event in emitted
    ] == list(range(1, record_count + 1))


def test_exact_manual_decrement_survives_unrelated_frame_displacement():
    emitted = []
    tracker = _instance_manual_tracker(emitted)
    instance = bytes.fromhex("1122334455667788")

    tracker.observe_frame(
        _manual_decrement_frame(
            seq=900,
            quantity=8,
            source_instance=instance,
        )
    )
    for index in range(3):
        tracker.observe_frame(
            _frame(0x2000 + index, seq=947 + index * 10, length=10)
        )
    tracker.observe_frame(_frame(0x0E6A, seq=977))
    tracker.register(
        replace(
            _storage_event(
                quantity=8,
                seq=977,
                storage_instance=f"0x{instance.hex()}",
            ),
            event_type="storage_record",
        )
    )
    tracker.finalize_all()

    assert len(emitted) == 1
    assert emitted[0].event_type == "storage_delta"
    assert emitted[0].source == "Player Inventory"
    assert emitted[0].extra["deposit_origin_evidence"]["manual_decrement"][
        "confidence"
    ] == "observed"


@pytest.mark.parametrize(
    ("unrelated_frames", "expected_manual"),
    ((0, True), (1, True), (2, False)),
)
def test_quantity_only_decrement_is_limited_to_two_successor_frames(
    unrelated_frames,
    expected_manual,
):
    emitted = []
    tracker = DepositOriginTracker(
        decrement_specs=(DecrementSpec(0x11AD, 47, 27),),
        emit=emitted.append,
    )
    instance = bytes.fromhex("1122334455667788")
    tracker.observe_frame(
        _manual_decrement_frame(
            seq=900,
            quantity=8,
            source_instance=instance,
        )
    )
    sequence = 947
    for index in range(unrelated_frames):
        tracker.observe_frame(_frame(0x2000 + index, seq=sequence, length=10))
        sequence += 10
    tracker.observe_frame(_frame(0x0E6A, seq=sequence))
    original = replace(
        _storage_event(quantity=8, seq=sequence),
        event_type="storage_record",
    )
    tracker.register(original)
    tracker.finalize_all()

    if expected_manual:
        assert len(emitted) == 1
        assert emitted[0].event_type == "storage_delta"
        assert emitted[0].source == "Player Inventory"
        manual = emitted[0].extra["deposit_origin_evidence"]["manual_decrement"]
        assert manual["confidence"] == "heuristic"
        assert manual["match_kind"] == "quantity-only"
    else:
        assert emitted == [original]


def test_one_manual_decrement_cannot_classify_two_storage_wrappers():
    emitted = []
    tracker = _instance_manual_tracker(emitted)
    instance = bytes.fromhex("1122334455667788")

    tracker.observe_frame(
        _manual_decrement_frame(
            seq=900,
            quantity=1,
            source_instance=instance,
        )
    )
    for index, sequence in enumerate((947, 952)):
        tracker.observe_frame(_frame(0x0E6A, seq=sequence))
        tracker.register(
            replace(
                _storage_event(
                    item_id=7002 + index,
                    quantity=1,
                    seq=sequence,
                    storage_instance=f"0x{instance.hex()}",
                ),
                event_type="storage_record",
            )
        )
    tracker.finalize_all()

    assert [
        (event.item_id, event.event_type, event.source) for event in emitted
    ] == [
        (7002, "storage_delta", "Player Inventory"),
        (7003, "storage_record", None),
    ]


def test_competing_exact_decrements_leave_storage_origin_neutral():
    emitted = []
    tracker = _instance_manual_tracker(emitted)
    instance = bytes.fromhex("1122334455667788")

    for sequence in (800, 847):
        tracker.observe_frame(
            _manual_decrement_frame(
                seq=sequence,
                quantity=1,
                source_instance=instance,
            )
        )
    tracker.observe_frame(_frame(0x0E6A, seq=894))
    original = replace(
        _storage_event(
            quantity=1,
            seq=894,
            storage_instance=f"0x{instance.hex()}",
        ),
        event_type="storage_record",
    )
    tracker.register(original)
    tracker.finalize_all()

    assert emitted == [original]
    assert emitted[0].event_type == "storage_record"
    assert emitted[0].source is None
    assert "deposit_origin_evidence" not in emitted[0].extra


def test_competing_structural_decrements_leave_storage_origin_neutral():
    emitted = []
    tracker = _instance_manual_tracker(emitted)
    source_instances = (
        bytes.fromhex("1020304050607080"),
        bytes.fromhex("1122334455667788"),
    )
    destination_instance = bytes.fromhex("8877665544332211")

    for sequence, instance in zip((800, 847), source_instances):
        tracker.observe_frame(
            _manual_decrement_frame(
                seq=sequence,
                quantity=1,
                source_instance=instance,
            )
        )
    tracker.observe_frame(_frame(0x0E6A, seq=894))
    original = replace(
        _storage_event(
            quantity=1,
            seq=894,
            storage_instance=f"0x{destination_instance.hex()}",
        ),
        event_type="storage_record",
    )
    tracker.register(original)
    tracker.finalize_all()

    assert emitted == [original]


def test_ambiguous_decrement_contenders_are_not_reused_later():
    emitted = []
    tracker = _instance_manual_tracker(emitted)
    source_instances = (
        bytes.fromhex("1020304050607080"),
        bytes.fromhex("1122334455667788"),
    )
    for sequence, instance in zip((800, 847), source_instances):
        tracker.observe_frame(
            _manual_decrement_frame(
                seq=sequence,
                quantity=1,
                source_instance=instance,
            )
        )

    originals = []
    for item_id, sequence, destination_instance in (
        (7002, 894, bytes.fromhex("8877665544332211")),
        (7003, 899, source_instances[0]),
    ):
        tracker.observe_frame(_frame(0x0E6A, seq=sequence))
        original = replace(
            _storage_event(
                item_id=item_id,
                quantity=1,
                seq=sequence,
                storage_instance=f"0x{destination_instance.hex()}",
            ),
            event_type="storage_record",
        )
        originals.append(original)
        tracker.register(original)
    tracker.finalize_all()

    assert emitted == originals


def test_candidate_internal_ambiguity_quarantines_the_physical_frame():
    emitted = []
    tracker = DepositOriginTracker(
        decrement_specs=(
            DecrementSpec(
                0x1A32,
                52,
                42,
                source_instance_offset=34,
                repeat_stride=23,
            ),
        ),
        emit=emitted.append,
    )
    repeated_instance = bytes.fromhex("1122334455667788")
    unique_instance = bytes.fromhex("8877665544332211")
    decrement = bytearray(98)
    decrement[0:2] = len(decrement).to_bytes(2, "little")
    decrement[3:5] = (0x1A32).to_bytes(2, "little")
    for index, (quantity, instance) in enumerate(
        ((1, repeated_instance), (1, repeated_instance), (2, unique_instance))
    ):
        delta = index * 23
        decrement[34 + delta : 42 + delta] = instance
        decrement[42 + delta : 46 + delta] = quantity.to_bytes(4, "little")
    tracker.observe_frame(
        BDOFrame(0, bytes(decrement), PacketContext(999.0, FLOW), 900)
    )

    originals = []
    for item_id, sequence, quantity, instance in (
        (7002, 998, 1, repeated_instance),
        (7003, 1003, 2, unique_instance),
    ):
        tracker.observe_frame(_frame(0x0E6A, seq=sequence))
        original = replace(
            _storage_event(
                item_id=item_id,
                quantity=quantity,
                seq=sequence,
                storage_instance=f"0x{instance.hex()}",
            ),
            event_type="storage_record",
        )
        originals.append(original)
        tracker.register(original)
    tracker.finalize_all()

    assert emitted == originals


def test_unique_exact_decrement_outranks_structural_candidate():
    emitted = []
    tracker = _instance_manual_tracker(emitted)
    structural_instance = bytes.fromhex("1020304050607080")
    exact_instance = bytes.fromhex("1122334455667788")

    for sequence, instance in (
        (800, structural_instance),
        (847, exact_instance),
    ):
        tracker.observe_frame(
            _manual_decrement_frame(
                seq=sequence,
                quantity=1,
                source_instance=instance,
            )
        )
    tracker.observe_frame(_frame(0x0E6A, seq=894))
    tracker.register(
        replace(
            _storage_event(
                quantity=1,
                seq=894,
                storage_instance=f"0x{exact_instance.hex()}",
            ),
            event_type="storage_record",
        )
    )
    tracker.finalize_all()

    assert len(emitted) == 1
    assert emitted[0].event_type == "storage_delta"
    assert emitted[0].source == "Player Inventory"
    manual = emitted[0].extra["deposit_origin_evidence"]["manual_decrement"]
    assert manual["confidence"] == "observed"
    assert manual["instance_matches_destination"] is True


@pytest.mark.parametrize(
    ("limit_name", "limit"),
    (
        ("MAX_MANUAL_CANDIDATES_PER_FLOW", 1),
        ("MAX_MANUAL_CANDIDATES_TOTAL", 1),
        ("MAX_MANUAL_CANDIDATE_BYTES_PER_FLOW", 47),
        ("MAX_MANUAL_CANDIDATE_BYTES_TOTAL", 47),
    ),
)
def test_manual_candidate_cap_pressure_does_not_manufacture_uniqueness(
    limit_name,
    limit,
):
    emitted = []
    tracker = _instance_manual_tracker(emitted)
    setattr(tracker, limit_name, limit)
    source_instances = (
        bytes.fromhex("1020304050607080"),
        bytes.fromhex("1122334455667788"),
    )
    destination_instance = bytes.fromhex("8877665544332211")

    for sequence, instance in zip((800, 847), source_instances):
        tracker.observe_frame(
            _manual_decrement_frame(
                seq=sequence,
                quantity=1,
                source_instance=instance,
            )
        )
    tracker.observe_frame(_frame(0x0E6A, seq=894))
    original = replace(
        _storage_event(
            quantity=1,
            seq=894,
            storage_instance=f"0x{destination_instance.hex()}",
        ),
        event_type="storage_record",
    )
    tracker.register(original)
    tracker.finalize_all()

    assert emitted == [original]


def test_candidate_cap_suppression_survives_decreasing_packet_timestamps():
    emitted = []
    tracker = _instance_manual_tracker(emitted)
    tracker.MAX_MANUAL_CANDIDATES_PER_FLOW = 1
    source_instances = (
        bytes.fromhex("1020304050607080"),
        bytes.fromhex("1122334455667788"),
    )
    destination_instance = bytes.fromhex("8877665544332211")

    for sequence, timestamp, instance in (
        (800, 1005.0, source_instances[0]),
        (847, 1000.0, source_instances[1]),
    ):
        tracker.observe_frame(
            _manual_decrement_frame(
                seq=sequence,
                quantity=1,
                source_instance=instance,
                timestamp=timestamp,
            )
        )
    tracker.observe_frame(_frame(0x0E6A, seq=894, timestamp=1000.0))
    original = replace(
        _storage_event(
            quantity=1,
            seq=894,
            timestamp=1000.0,
            storage_instance=f"0x{destination_instance.hex()}",
        ),
        event_type="storage_record",
    )
    tracker.register(original)
    tracker.finalize_all()

    assert emitted == [original]


def test_buffered_manual_pair_survives_a_newer_earlier_stream_timestamp():
    emitted = []
    tracker = _instance_manual_tracker(emitted)
    instance = bytes.fromhex("1122334455667788")

    tracker.observe_frame(_frame(0x2000, seq=890, timestamp=1005.0))
    tracker.observe_frame(
        _manual_decrement_frame(
            seq=900,
            quantity=8,
            source_instance=instance,
            timestamp=1001.0,
        )
    )
    tracker.observe_frame(_frame(0x0E6A, seq=947, timestamp=1001.0))
    tracker.register(
        replace(
            _storage_event(
                quantity=8,
                seq=947,
                timestamp=1001.0,
                storage_instance=f"0x{instance.hex()}",
            ),
            event_type="storage_record",
        )
    )
    tracker.finalize_all()

    assert len(emitted) == 1
    assert emitted[0].event_type == "storage_delta"
    assert emitted[0].source == "Player Inventory"


def test_stale_flush_expires_unclaimed_manual_decrements():
    emitted = []
    tracker = _instance_manual_tracker(emitted)
    instance = bytes.fromhex("1122334455667788")

    tracker.observe_frame(
        _manual_decrement_frame(
            seq=900,
            quantity=8,
            source_instance=instance,
            timestamp=1000.0,
        )
    )
    tracker.flush_stale(now=1000.0 + tracker.STALE_SECONDS + 0.1)
    tracker.observe_frame(
        _frame(
            0x0E6A,
            seq=947,
            timestamp=1000.0 + tracker.STALE_SECONDS + 0.1,
        )
    )
    original = replace(
        _storage_event(
            quantity=8,
            seq=947,
            timestamp=1000.0 + tracker.STALE_SECONDS + 0.1,
            storage_instance=f"0x{instance.hex()}",
        ),
        event_type="storage_record",
    )
    tracker.register(original)
    tracker.finalize_all()

    assert emitted == [original]


def test_manual_decrement_cannot_cross_flow_generation():
    emitted = []
    tracker = _instance_manual_tracker(emitted)
    instance = bytes.fromhex("1122334455667788")

    tracker.observe_frame(
        _manual_decrement_frame(
            seq=900,
            quantity=8,
            source_instance=instance,
            flow_generation=1,
        )
    )
    storage_frame = _frame(0x0E6A, seq=947)
    tracker.observe_frame(
        BDOFrame(
            storage_frame.index,
            storage_frame.message,
            PacketContext(
                storage_frame.context.timestamp,
                FLOW,
                flow_generation=2,
            ),
            storage_frame.stream_sequence,
        )
    )
    original = replace(
        _storage_event(
            quantity=8,
            seq=947,
            storage_instance=f"0x{instance.hex()}",
        ),
        event_type="storage_record",
        _flow_generation=2,
    )
    tracker.register(original)
    tracker.finalize_all()

    assert emitted == [original]


def test_flow_close_releases_unclaimed_manual_decrement():
    emitted = []
    tracker = _instance_manual_tracker(emitted)
    instance = bytes.fromhex("1122334455667788")
    tracker.observe_frame(
        _manual_decrement_frame(
            seq=900,
            quantity=8,
            source_instance=instance,
        )
    )

    tracker.close_flow(FLOW)
    tracker.observe_frame(_frame(0x0E6A, seq=947))
    original = replace(
        _storage_event(
            quantity=8,
            seq=947,
            storage_instance=f"0x{instance.hex()}",
        ),
        event_type="storage_record",
    )
    tracker.register(original)
    tracker.finalize_all()

    assert emitted == [original]


def test_gap_reset_rejects_pre_reset_decrement_retransmission():
    emitted = []
    tracker = _instance_manual_tracker(emitted)
    instance = bytes.fromhex("1122334455667788")
    old_decrement = _manual_decrement_frame(
        seq=900,
        quantity=8,
        source_instance=instance,
        flow_generation=3,
    )
    tracker.observe_frame(old_decrement)

    tracker.reset_flow(FLOW, 3, 1000)
    tracker.observe_frame(
        replace(
            old_decrement,
            context=PacketContext(1001.0, FLOW, flow_generation=3),
        )
    )
    storage_frame = _frame(0x0E6A, seq=1000, timestamp=1001.0)
    tracker.observe_frame(
        replace(
            storage_frame,
            context=PacketContext(1001.0, FLOW, flow_generation=3),
        )
    )
    original = replace(
        _storage_event(
            quantity=8,
            seq=1000,
            timestamp=1001.0,
            storage_instance=f"0x{instance.hex()}",
        ),
        event_type="storage_record",
        _flow_generation=3,
    )
    tracker.register(original)
    tracker.finalize_all()

    assert emitted == [original]


def test_manual_batch_owns_decrement_records_atomically_once():
    emitted = []
    tracker = DepositOriginTracker(
        decrement_specs=(
            DecrementSpec(
                0x1A32,
                52,
                42,
                source_instance_offset=34,
                repeat_stride=23,
            ),
        ),
        emit=emitted.append,
    )
    instances = (
        bytes.fromhex("1020304050607080"),
        bytes.fromhex("1122334455667788"),
    )
    quantities = (2, 8)
    decrement = bytearray(75)
    decrement[0:2] = len(decrement).to_bytes(2, "little")
    decrement[3:5] = (0x1A32).to_bytes(2, "little")
    for index, (quantity, instance) in enumerate(zip(quantities, instances)):
        delta = index * 23
        decrement[34 + delta : 42 + delta] = instance
        decrement[42 + delta : 46 + delta] = quantity.to_bytes(4, "little")
    tracker.observe_frame(
        BDOFrame(0, bytes(decrement), PacketContext(999.0, FLOW), 900)
    )

    for batch_index, sequence in enumerate((975, 1075)):
        tracker.observe_frame(_frame(0x0E6A, seq=sequence, length=100))
        for record_index, (quantity, instance) in enumerate(
            zip(quantities, instances),
            start=1,
        ):
            tracker.register(
                replace(
                    _storage_event(
                        item_id=7000 + batch_index * 10 + record_index,
                        quantity=quantity,
                        seq=sequence,
                        message_length=100,
                        record_offset=20 + (record_index - 1) * 30,
                        storage_instance=f"0x{instance.hex()}",
                    ),
                    event_type="storage_record",
                    record_index=record_index,
                    record_count=2,
                )
            )
    tracker.finalize_all()

    assert [
        (event.item_id, event.event_type, event.source) for event in emitted
    ] == [
        (7001, "storage_delta", "Player Inventory"),
        (7002, "storage_delta", "Player Inventory"),
        (7011, "storage_record", None),
        (7012, "storage_record", None),
    ]


def test_malformed_declared_decrement_geometry_is_not_downgraded():
    profile = OpcodeProfile(
        path=Path("synthetic-opcodes.json"),
        active=True,
        version=1,
        updated_at=None,
        calibration_item_id=None,
        specs={
            "SOURCE_STACK_DECREMENT": (
                {
                    "opcode": "0x1000",
                    "length": 47,
                    "quantity_removed_offset": 27,
                },
                {
                    "opcode": "0x1001",
                    "length": 47,
                    "quantity_removed_offset": 27,
                    "source_instance_offset": 45,
                },
            )
        },
    )

    with pytest.raises(
        ProfileError,
        match=r"SOURCE_STACK_DECREMENT\[1\].*source instance offset",
    ):
        _decrement_specs(profile)


def test_no_evidence_yields_unknown():
    emitted = []
    tracker = _tracker(emitted)
    tracker.observe_frame(_frame(0x0E6A, seq=1000))
    tracker.register(_storage_event(seq=1000))
    tracker.finalize_all()
    assert emitted[0].source is None


def test_companions_outrank_a_spurious_decrement_match():
    # Companions present AND a (possibly spurious) decrement match => worker,
    # NOT unknown. Companions have perfect separation; a quantity-only
    # decrement match collides for small quantities and must not veto them.
    # Evidence is still recorded truthfully for auditability.
    emitted = []
    tracker = _tracker(emitted)
    decrement = bytearray(52)
    decrement[0:2] = (52).to_bytes(2, "little")
    decrement[3:5] = (0x1A32).to_bytes(2, "little")
    decrement[42:46] = (1).to_bytes(4, "little")  # qty=1: the colliding value
    tracker.observe_frame(
        BDOFrame(
            index=0,
            message=bytes(decrement),
            context=PacketContext(timestamp=999.0, flow=FLOW),
            stream_sequence=900,
        )
    )
    delta, first, second = _worker_chain()
    tracker.observe_frame(delta)
    tracker.register(_storage_event(quantity=1, seq=1000, message_length=80))
    tracker.observe_frame(first)
    tracker.observe_frame(second)
    tracker.finalize_all()
    assert emitted[0].source == "Worker Production"
    evidence = emitted[0].extra["deposit_origin_evidence"]
    assert evidence["worker_companions"] is True
    assert evidence["matching_decrement"] is True


def test_multi_record_worker_batch_agrees_across_records():
    # The exact reported bug: two records of ONE worker batch frame, the qty=1
    # record spuriously matching a decrement while the qty=25 record does not.
    # Both must classify worker; companions are shared by the whole frame.
    emitted = []
    tracker = _tracker(emitted)
    decrement = bytearray(60)
    decrement[0:2] = (60).to_bytes(2, "little")
    decrement[3:5] = (0x1A32).to_bytes(2, "little")
    decrement[42:46] = (1).to_bytes(4, "little")
    tracker.observe_frame(
        BDOFrame(
            index=0,
            message=bytes(decrement),
            context=PacketContext(timestamp=999.0, flow=FLOW),
            stream_sequence=900,
        )
    )
    delta, first, second = _worker_chain()
    tracker.observe_frame(delta)
    # Both records share the frame's stream_sequence.
    tracker.register(
        _storage_event(item_id=4409, quantity=1, seq=1000, message_length=80)
    )
    tracker.register(
        _storage_event(item_id=4004, quantity=25, seq=1000, message_length=80)
    )
    tracker.observe_frame(first)
    tracker.observe_frame(second)
    tracker.finalize_all()
    sources = [event.source for event in emitted]
    assert sources == ["Worker Production", "Worker Production"]


def test_companions_already_in_segment_finalize_immediately():
    # The frame tap runs ahead of the event decoder, so companions in the
    # same TCP segment are visible at registration time.
    emitted = []
    tracker = _tracker(emitted)
    delta, first, second = _worker_chain()
    tracker.observe_frame(delta)
    tracker.observe_frame(first)
    tracker.observe_frame(second)
    tracker.register(_storage_event(seq=1000, message_length=80))
    assert emitted and emitted[0].source == "Worker Production"


def test_worker_chain_resynchronizes_generic_tap_after_midframe_start():
    """A known delta boundary restores the generic tap after attachment."""
    emitted = []
    tracker = _tracker(emitted)
    tapped_frames = []

    def observe_frame(frame):
        tapped_frames.append(frame)
        tracker.observe_frame(frame)

    def handle_record(record, raw_message):
        tracker.register(
            toolkit_event_from_record(record),
            raw_message=raw_message,
        )

    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x0E6A,
        item_offset=37,
        quantity_offset=41,
        min_message_length=80,
        source_context_offset=8,
        record_count_offset=6,
        storage_instance_offset=72,
        single_record_message_length=80,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=handle_record,
        frame_observer=observe_frame,
        stream_observer=tracker.observe_stream,
    )
    delta, first, second = _worker_chain()
    delta_message = bytearray(delta.message)
    delta_message[6:8] = (1).to_bytes(2, "little")
    delta_message[8:12] = (0x0020).to_bytes(4, "little")
    delta_message[37:41] = (7002).to_bytes(4, "little")
    delta_message[41:45] = (25).to_bytes(4, "little")
    delta_message[72:80] = b"\x22" * 8

    # 0x1000 is a plausible but incomplete leading length.  The generic tap
    # must now skip it and use the known delta opcode as a frame boundary.
    payload = b"\x00\x10" + bytes(delta_message) + first.message + second.message
    engine.process_tcp_segment(
        source_ip=FLOW.source_ip,
        source_port=FLOW.source_port,
        destination_ip=FLOW.destination_ip,
        destination_port=FLOW.destination_port,
        sequence=998,
        payload=payload,
        timestamp=1000.0,
    )

    assert [frame.opcode for frame in tapped_frames] == [
        0x0E6A,
        first.opcode,
        second.opcode,
    ]
    assert emitted and emitted[0].source == "Worker Production"


def _write_july17_unknown_operation_profile(tmp_path):
    profile = tmp_path / "opcodes.local"
    profile.write_text(
        json.dumps(
            {
                "version": 1,
                "profile_active": True,
                "specs": {
                    "SOURCE_STACK_DECREMENT": [
                        {
                            "event": "SOURCE_STACK_DECREMENT",
                            "opcode": "0x11AD",
                            "length": 47,
                            "quantity_removed_offset": 27,
                        }
                    ],
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
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    return profile


def _july17_unknown_operation_storage(
    records,
    *,
    token=bytes.fromhex("3141592653589793"),
    storage_instances=None,
):
    if storage_instances is not None and len(storage_instances) != len(records):
        raise ValueError("storage_instances must align with records")
    stride = 222
    message = bytearray(257 + (len(records) - 1) * stride)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x126D).to_bytes(2, "little")
    message[6] = 3  # unfamiliar operation discriminator
    message[7:15] = token
    message[16:18] = len(records).to_bytes(2, "little")
    message[27:31] = (0x0020).to_bytes(4, "little")
    for index, (item_id, quantity) in enumerate(records):
        item_offset = 36 + index * stride
        message[item_offset : item_offset + 4] = item_id.to_bytes(4, "little")
        message[item_offset + 4 : item_offset + 8] = quantity.to_bytes(4, "little")
        message[item_offset + 12 : item_offset + 20] = b"\xff" * 8
        instance = (
            bytes([index + 1]) * 8
            if storage_instances is None
            else storage_instances[index]
        )
        message[item_offset + 35 : item_offset + 43] = instance
    return bytes(message)


def _july17_manual_decrement(quantity, source_instance=None):
    message = bytearray(47)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x11AD).to_bytes(2, "little")
    message[27:31] = quantity.to_bytes(4, "little")
    if source_instance is not None:
        message[35:43] = source_instance
    return bytes(message)


def _july17_inventory_receipt(item_id, quantity, item_instance):
    message = bytearray(254)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x194A).to_bytes(2, "little")
    message[27:31] = bytes.fromhex("d0f205a3")  # Storage
    message[31:35] = item_id.to_bytes(4, "little")
    message[35:39] = quantity.to_bytes(4, "little")
    message[43:51] = b"\xff" * 8
    message[66:74] = item_instance
    return bytes(message)


def _current_companions(token):
    first = bytearray(64)
    first[0:2] = len(first).to_bytes(2, "little")
    first[3:5] = (0x1A59).to_bytes(2, "little")
    first[5:13] = token
    second = bytearray(30)
    second[0:2] = len(second).to_bytes(2, "little")
    second[3:5] = (0x155E).to_bytes(2, "little")
    second[5:13] = token
    return bytes(first), bytes(second)


def _collect_synthetic_current_storage(profile, payload, event_filter=None):
    return _collect_synthetic_current_segments(
        profile,
        (payload,),
        event_filter,
    )


def _collect_synthetic_current_segments(profile, payloads, event_filter=None):
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=event_filter,
        opcode_profile=profile,
    )
    sequence = 1000
    for index, payload in enumerate(payloads):
        collector.engine.process_tcp_segment(
            source_ip=FLOW.source_ip,
            source_port=FLOW.source_port,
            destination_ip=FLOW.destination_ip,
            destination_port=FLOW.destination_port,
            sequence=sequence & 0xFFFFFFFF,
            payload=payload,
            timestamp=1000.0 + index * 0.01,
        )
        sequence += len(payload)
    collector.engine.finish()
    collector.finalize()
    return list(collector.drain_events())


def test_manual_ledger_correlates_across_tcp_sequence_wrap():
    instance = bytes.fromhex("1122334455667788")
    payload = _july17_manual_decrement(8, instance) + (
        _july17_unknown_operation_storage(
            ((7307, 8),),
            storage_instances=(instance,),
        )
    )
    collector = _EventCollector(
        server_ports=(8889,),
        opcode_profile=JULY17_OPCODE_PROFILE,
    )
    collector.engine.process_tcp_segment(
        source_ip=FLOW.source_ip,
        source_port=FLOW.source_port,
        destination_ip=FLOW.destination_ip,
        destination_port=FLOW.destination_port,
        sequence=0xFFFFFFEF,
        payload=payload,
        timestamp=1000.0,
        syn=True,
    )
    collector.engine.finish()
    collector.finalize()
    events = list(collector.drain_events())

    assert len(events) == 1
    assert events[0].event_type == "storage_delta"
    assert events[0].source == "Player Inventory"
    assert (events[0].item_id, events[0].quantity) == (7307, 8)


@pytest.mark.parametrize("segment_layout", ("coalesced", "fragmented"))
def test_manual_ledger_survives_24_alternating_transfers(segment_layout):
    expected_manual = []
    expected_receipts = []
    messages = []
    worker_token = bytes.fromhex("3141592653589793")
    worker_instance = bytes.fromhex("8877665544332211")

    for index in range(24):
        if index == 20:
            # A matching ambient decrement must not outrank the worker's
            # operation-specific companion chain.
            messages.append(_july17_manual_decrement(1, worker_instance))
            messages.append(
                _july17_unknown_operation_storage(
                    ((4607, 1),),
                    token=worker_token,
                    storage_instances=(worker_instance,),
                )
            )
            messages.extend(_current_companions(worker_token))

        item_id = 7003 if index % 2 == 0 else 1000306
        quantity = 1 if index % 2 else (index % 5) + 2
        instance = (0x1020304050607000 + index).to_bytes(8, "little")
        token = (0x2020304050607000 + index).to_bytes(8, "little")
        messages.extend(
            (
                _july17_manual_decrement(quantity, instance),
                _july17_unknown_operation_storage(
                    ((item_id, quantity),),
                    token=token,
                    storage_instances=(instance,),
                ),
                _july17_inventory_receipt(item_id, quantity, instance),
            )
        )
        expected_manual.append((item_id, quantity, f"0x{instance.hex()}"))
        expected_receipts.append((item_id, quantity, f"0x{instance.hex()}"))

    payload = b"".join(messages)
    if segment_layout == "coalesced":
        payloads = (payload,)
    else:
        first_cut = len(payload) // 3 + 7
        second_cut = 2 * len(payload) // 3 + 19
        # Both cuts intentionally land inside messages, so this also exercises
        # TCP reassembly rather than merely dividing at application boundaries.
        payloads = (
            payload[:first_cut],
            payload[first_cut:second_cut],
            payload[second_cut:],
        )

    events = _collect_synthetic_current_segments(
        JULY17_OPCODE_PROFILE,
        payloads,
    )

    assert not [event for event in events if event.event_type == "storage_record"]
    manual = [
        event
        for event in events
        if event.event_type == "storage_delta"
        and event.source == "Player Inventory"
    ]
    assert sorted(
        (event.item_id, event.quantity, event.storage_instance) for event in manual
    ) == sorted(expected_manual)
    receipts = [event for event in events if event.event_type == "item_received"]
    assert sorted(
        (event.item_id, event.quantity, event.item_instance) for event in receipts
    ) == sorted(expected_receipts)
    assert {event.source for event in receipts} == {"Storage"}

    worker = [event for event in events if event.item_id == 4607]
    assert len(worker) == 1
    assert worker[0].event_type == "storage_delta"
    assert worker[0].source == "Worker Production"
    worker_evidence = worker[0].extra["deposit_origin_evidence"]
    assert worker_evidence["worker_companions"] is True
    assert worker_evidence["matching_decrement"] is True


def test_unknown_operation_manual_is_promoted_before_filtering(tmp_path):
    profile = _write_july17_unknown_operation_profile(tmp_path)
    storage = _july17_unknown_operation_storage(((7307, 8),))
    events = _collect_synthetic_current_storage(
        profile,
        _july17_manual_decrement(8) + storage,
        EventFilter(
            event_types={"storage_delta"},
            sources={"Player Inventory"},
            storage_ids={0x0020},
        ),
    )

    assert len(events) == 1
    event = events[0]
    assert (event.item_id, event.quantity, event.storage_name) == (
        7307,
        8,
        "Heidel",
    )
    assert event.source == "Player Inventory"
    assert event.event_type == "storage_delta"
    manual_evidence = event.extra["deposit_origin_evidence"]
    assert manual_evidence["worker_companions"] is False
    assert manual_evidence["matching_decrement"] is True
    assert manual_evidence["manual_decrement"] == {
        "opcode": "0x11AD",
        "message_length": 47,
        "quantity_offset": 27,
        "match_kind": "quantity-only",
        "confidence": "heuristic",
        "record_index": 1,
    }
    assert event.extra["storage_operation_evidence"] == {
        "wire_operation": "unknown",
        "inferred_operation": "live",
        "signal": "matching_decrement",
    }


def test_unknown_operation_without_live_evidence_stays_neutral(tmp_path):
    profile = _write_july17_unknown_operation_profile(tmp_path)
    storage = _july17_unknown_operation_storage(((7307, 8),))
    events = _collect_synthetic_current_storage(profile, storage)

    assert len(events) == 1
    event = events[0]
    assert event.event_type == "storage_record"
    assert event.source is None
    assert "deposit_origin_evidence" not in event.extra


def test_incomplete_unknown_operation_batch_finalizes_neutral():
    emitted = []
    tracker = _tracker(emitted)
    event = BDOEvent(
        event_type="storage_record",
        timestamp=1000.0,
        flow=Flow("10.0.0.1", 8889, "10.0.0.2", 50000),
        item_id=7307,
        quantity=8,
        opcode=0x126D,
        message_length=479,
        record_offset=36,
        record_index=1,
        record_count=2,
        extra={"stream_sequence": 1000},
    )

    tracker.register(event)
    tracker.finalize_all()

    assert emitted == [event]
    assert emitted[0].source is None


def test_unknown_operation_manual_batch_is_promoted_atomically(tmp_path):
    profile = _write_july17_unknown_operation_profile(tmp_path)
    storage = _july17_unknown_operation_storage(((7307, 8), (4003, 21)))
    events = _collect_synthetic_current_storage(
        profile,
        _july17_manual_decrement(8) + storage,
        EventFilter(event_types={"storage_delta"}),
    )

    assert [
        (event.item_id, event.quantity, event.record_index, event.record_count)
        for event in events
    ] == [(7307, 8, 1, 2), (4003, 21, 2, 2)]
    assert {event.source for event in events} == {"Player Inventory"}
    assert {event.event_type for event in events} == {"storage_delta"}
    assert all(
        event.extra["deposit_origin_evidence"][
            "matching_decrement_record_indexes"
        ]
        == (1,)
        for event in events
    )


def test_unknown_operation_worker_chain_is_promoted(tmp_path):
    profile = _write_july17_unknown_operation_profile(tmp_path)
    storage = _july17_unknown_operation_storage(((4802, 1),))
    first, second = _current_companions(bytes.fromhex("3141592653589793"))
    events = _collect_synthetic_current_storage(
        profile,
        _july17_manual_decrement(1) + storage + first + second,
        EventFilter(event_types={"storage_delta"}),
    )

    assert len(events) == 1
    event = events[0]
    assert event.event_type == "storage_delta"
    assert event.source == "Worker Production"
    assert event.extra["deposit_origin_evidence"]["matching_decrement"] is True
    assert event.extra["storage_operation_evidence"]["signal"] == (
        "worker_companions"
    )


def test_interleaved_manual_storage_does_not_hide_worker_from_filter(tmp_path):
    profile = _write_july17_unknown_operation_profile(tmp_path)
    worker_token = bytes.fromhex("3141592653589793")
    manual_token = bytes.fromhex("1021324354657687")
    worker_storage = _july17_unknown_operation_storage(
        ((4802, 1),),
        token=worker_token,
    )
    manual_storage = _july17_unknown_operation_storage(
        ((15156, 8),),
        token=manual_token,
    )
    first, second = _current_companions(worker_token)

    events = _collect_synthetic_current_storage(
        profile,
        worker_storage
        + _july17_manual_decrement(8)
        + manual_storage
        + first
        + second,
        EventFilter(event_types={"item_received", "storage_delta"}),
    )

    assert [
        (event.item_id, event.event_type, event.source)
        for event in events
    ] == [
        (4802, "storage_delta", "Worker Production"),
        (15156, "storage_delta", "Player Inventory"),
    ]


def test_crossed_storage_record_body_is_not_treated_as_token_prefix(tmp_path):
    profile = _write_july17_unknown_operation_profile(tmp_path)
    token_a = bytes.fromhex("3141592653589793")
    token_b = bytes.fromhex("1021324354657687")
    storage_a = _july17_unknown_operation_storage(
        ((4802, 1),),
        token=token_a,
    )
    storage_b = bytearray(
        _july17_unknown_operation_storage(
            ((15156, 1),),
            token=token_b,
        )
    )
    # This is inside record one (whose authoritative boundary is 36), not in
    # the transaction prefix. Observer-first delivery sees the raw wrapper
    # before target decoding registers that boundary.
    storage_b[71:79] = token_a
    first, second = _current_companions(token_a)
    payload = storage_a + bytes(storage_b) + first + second

    delivered = _collect_synthetic_current_storage(
        profile,
        payload,
        EventFilter(event_types={"item_received", "storage_delta"}),
    )
    assert [
        (event.item_id, event.source) for event in delivered
    ] == [(4802, "Worker Production")]

    all_events = _collect_synthetic_current_storage(
        profile,
        payload,
        EventFilter.all(),
    )
    assert [
        (event.item_id, event.event_type, event.source)
        for event in all_events
    ] == [
        (4802, "storage_delta", "Worker Production"),
        (15156, "storage_record", None),
    ]


def test_reused_token_ambiguity_stays_neutral_before_live_filter(tmp_path):
    profile = _write_july17_unknown_operation_profile(tmp_path)
    token = bytes.fromhex("3141592653589793")
    storage_a = _july17_unknown_operation_storage(
        ((4802, 1),),
        token=token,
    )
    storage_b = _july17_unknown_operation_storage(
        ((15156, 1),),
        token=token,
    )
    first, second = _current_companions(token)
    payload = storage_a + storage_b + first + second

    assert _collect_synthetic_current_storage(
        profile,
        payload,
        EventFilter(event_types={"item_received", "storage_delta"}),
    ) == []
    all_events = _collect_synthetic_current_storage(
        profile,
        payload,
        EventFilter.all(),
    )
    assert [
        (event.item_id, event.event_type, event.source)
        for event in all_events
    ] == [
        (4802, "storage_record", None),
        (15156, "storage_record", None),
    ]
    assert all(
        "deposit_origin_evidence" not in event.extra for event in all_events
    )


def test_whole_segment_dual_token_pair_stays_neutral_after_older_closes(tmp_path):
    profile = _write_july17_unknown_operation_profile(tmp_path)
    token_a = bytes.fromhex("3141592653589793")
    token_b = bytes.fromhex("1021324354657687")
    storage_a = _july17_unknown_operation_storage(
        ((4802, 1),),
        token=token_a,
    )
    storage_b = _july17_unknown_operation_storage(
        ((15156, 1),),
        token=token_b,
    )
    first, second = _current_companions(token_a)
    first_message = bytearray(first)
    second_message = bytearray(second)
    first_message[14:22] = token_b
    second_message[14:22] = token_b
    trailing = b"".join(
        _frame(0x3000 + index, 0).message
        for index in range(29)
    )
    payload = (
        storage_a
        + storage_b
        + bytes(first_message)
        + bytes(second_message)
        + trailing
    )

    delivered = _collect_synthetic_current_storage(
        profile,
        payload,
        EventFilter(event_types={"item_received", "storage_delta"}),
    )
    assert delivered == []

    all_events = _collect_synthetic_current_storage(
        profile,
        payload,
        EventFilter.all(),
    )
    storage_records = [
        event for event in all_events if event.event_type == "storage_record"
    ]
    assert [event.item_id for event in storage_records] == [4802, 15156]
    assert all(event.source is None for event in storage_records)
    assert all("deposit_origin_evidence" not in event.extra for event in storage_records)


def test_unknown_companion_opcodes_are_discovered_once_for_multi_record_batch():
    emitted = []
    observations = []
    tracker = DepositOriginTracker(
        decrement_specs=(),
        emit=emitted.append,
        origin_observer=observations.append,
    )
    delta, first, second = _worker_chain(
        delta_opcode=0x0D7E,
        first=0x0F7E,
        second=0x0DE1,
    )
    tracker.observe_frame(delta)
    tracker.register(
        _storage_event(item_id=5004, quantity=6, seq=1000, message_length=80)
    )
    tracker.register(
        _storage_event(item_id=4604, quantity=25, seq=1000, message_length=80)
    )
    tracker.observe_frame(first)
    tracker.observe_frame(second)
    tracker.finalize_all()

    assert [event.source for event in emitted] == [
        "Worker Production",
        "Worker Production",
    ]
    assert len(observations) == 1
    assert observations[0].companion_opcodes == (0x0F7E, 0x0DE1)


def test_two_interleaved_workers_keep_distinct_token_ownership():
    emitted = []
    tracker = _tracker(emitted)
    token_a = bytes.fromhex("07feabbfc91b8e00")
    token_b = bytes.fromhex("3141592653589793")
    delta_a, first_a, second_a = _worker_chain(token=token_a)
    delta_b, first_b, second_b = _worker_chain(delta_seq=1080, token=token_b)

    tracker.observe_frame(delta_a)
    tracker.register(_storage_event(item_id=7002, seq=1000, message_length=80))
    tracker.observe_frame(delta_b)
    tracker.register(_storage_event(item_id=7003, seq=1080, message_length=80))

    sequence = 1160
    for frame in (first_a, first_b, second_a, second_b):
        tracker.observe_frame(
            BDOFrame(frame.index, frame.message, frame.context, sequence)
        )
        sequence += len(frame.message)
    tracker.finalize_all()

    assert [event.source for event in emitted] == [
        "Worker Production",
        "Worker Production",
    ]
    digests = {
        event.extra["deposit_origin_evidence"]["companion_chain"][
            "shared_token_digest"
        ]
        for event in emitted
    }
    assert len(digests) == 2


def test_one_companion_pair_cannot_serve_two_distinct_tokens():
    emitted = []
    tracker = _tracker(emitted)
    token_a = bytes.fromhex("07feabbfc91b8e00")
    token_b = bytes.fromhex("3141592653589793")
    delta_a, first, second = _worker_chain(token=token_a)
    delta_b, _, _ = _worker_chain(delta_seq=1080, token=token_b)
    first_message = bytearray(first.message)
    second_message = bytearray(second.message)
    first_message[5:13] = token_b
    second_message[14:22] = token_b

    tracker.observe_frame(delta_a)
    tracker.register(_storage_event(item_id=7002, seq=1000, message_length=80))
    tracker.observe_frame(delta_b)
    tracker.register(_storage_event(item_id=7003, seq=1080, message_length=80))
    tracker.observe_frame(
        BDOFrame(4, bytes(first_message), first.context, 1160)
    )
    tracker.observe_frame(
        BDOFrame(5, bytes(second_message), second.context, 1218)
    )
    tracker.finalize_all()

    assert [event.source for event in emitted] == [None, None]


def test_interleaved_storage_with_reused_token_is_ambiguous():
    emitted = []
    tracker = _tracker(emitted)
    delta, first, second = _worker_chain()
    tracker.observe_frame(delta)
    tracker.register(_storage_event(seq=1000, message_length=80))

    next_delta = BDOFrame(3, delta.message, delta.context, 1080)
    tracker.observe_frame(next_delta)
    tracker.register(
        _storage_event(
            item_id=15156,
            quantity=1,
            seq=1080,
            message_length=80,
        )
    )
    tracker.observe_frame(BDOFrame(4, first.message, first.context, 1160))
    tracker.observe_frame(BDOFrame(5, second.message, second.context, 1218))
    tracker.finalize_all()

    assert [event.source for event in emitted] == [None, None]


def test_contested_pair_history_pressure_never_restores_worker_trust():
    emitted = []
    tracker = _tracker(emitted)
    tracker.COMPANION_PAIR_HISTORY_LIMIT = 1
    delta, first, second = _worker_chain()

    tracker.observe_frame(delta)
    tracker.register(_storage_event(item_id=7002, seq=1000, message_length=80))
    tracker.observe_frame(BDOFrame(3, delta.message, delta.context, 1080))
    tracker.register(_storage_event(item_id=7003, seq=1080, message_length=80))
    tracker.observe_frame(BDOFrame(4, first.message, first.context, 1160))
    tracker.observe_frame(BDOFrame(5, second.message, second.context, 1218))
    assert tracker._contested_companion_pairs

    # Force the bounded FIFO to retire that exact pair. The affected flow must
    # remain fail-closed instead of allowing the remaining claimant to borrow
    # evidence that was already proven contested.
    other_flow = FlowKey("10.0.0.3", 8889, "10.0.0.4", 50001)
    tracker._mark_companion_pair_contested((other_flow, 1, 2))
    assert FLOW in tracker._companion_contest_overflow_flows
    tracker.observe_frame(_frame(0x2222, 1241))
    tracker.finalize_all()

    assert [event.source for event in emitted] == [None, None]


def test_contest_overflow_clears_previously_accumulated_worker_candidate():
    emitted = []
    tracker = _tracker(emitted)
    tracker.COMPANION_PAIR_HISTORY_LIMIT = 1
    delta, first, second = _worker_chain()

    tracker.observe_frame(delta)
    tracker.register(_storage_event(item_id=7002, seq=1000, message_length=80))
    tracker.observe_frame(_frame(0x2222, 1080, length=10))
    tracker.observe_frame(BDOFrame(4, first.message, first.context, 1090))
    tracker.observe_frame(BDOFrame(5, second.message, second.context, 1148))
    assert len(tracker._pending[0].candidate_observations) == 1

    tracker._mark_companion_pair_contested((FLOW, 2000, 2058))
    other_flow = FlowKey("10.0.0.3", 8889, "10.0.0.4", 50001)
    tracker._mark_companion_pair_contested((other_flow, 1, 2))
    assert FLOW in tracker._companion_contest_overflow_flows
    assert tracker._pending[0].candidate_observations == {}

    tracker.finalize_all()
    assert [(event.item_id, event.source) for event in emitted] == [
        (7002, None)
    ]


def test_operation_cap_eviction_does_not_confirm_partial_worker_chain():
    emitted = []
    tracker = _tracker(emitted)
    tracker.MAX_PENDING_OPERATIONS_PER_FLOW = 1
    delta, first, second = _worker_chain()

    tracker.observe_frame(delta)
    tracker.register(_storage_event(item_id=7002, seq=1000, message_length=80))
    tracker.observe_frame(_frame(0x2222, 1080, length=10))
    tracker.observe_frame(BDOFrame(4, first.message, first.context, 1090))
    tracker.observe_frame(BDOFrame(5, second.message, second.context, 1148))
    assert emitted == []
    assert len(tracker._pending[0].candidate_observations) == 1

    next_delta, _, _ = _worker_chain(
        delta_seq=1171,
        token=bytes.fromhex("3141592653589793"),
    )
    tracker.observe_frame(next_delta)
    tracker.register(_storage_event(item_id=7003, seq=1171, message_length=80))
    assert [(event.item_id, event.source) for event in emitted] == [
        (7002, None)
    ]
    tracker.finalize_all()
    assert [(event.item_id, event.source) for event in emitted] == [
        (7002, None),
        (7003, None),
    ]


def test_unregistered_next_storage_with_reused_token_is_not_borrowed():
    emitted = []
    tracker = _tracker(emitted)
    delta, first, second = _worker_chain()
    tracker.observe_frame(delta)
    tracker.register(_storage_event(seq=1000, message_length=80))

    # The raw tap observes the next storage wrapper before its target record is
    # necessarily registered. Repeating the same token in that wrapper is
    # already enough to make ownership ambiguous and must fail closed.
    next_delta = BDOFrame(3, delta.message, delta.context, 1080)
    tracker.observe_frame(next_delta)
    tracker.observe_frame(BDOFrame(4, first.message, first.context, 1160))
    tracker.observe_frame(BDOFrame(5, second.message, second.context, 1218))
    tracker.finalize_all()

    assert emitted[0].source is None


def test_worker_companions_survive_more_than_eight_unrelated_messages():
    emitted = []
    tracker = _tracker(emitted)
    delta, first, second = _worker_chain()
    tracker.observe_frame(delta)
    tracker.register(_storage_event(seq=1000, message_length=80))

    next_sequence = 1080
    for index in range(12):
        unrelated = _frame(0x2000 + index, next_sequence, length=10)
        tracker.observe_frame(unrelated)
        next_sequence += len(unrelated.message)
    tracker.observe_frame(
        BDOFrame(first.index, first.message, first.context, next_sequence)
    )
    next_sequence += len(first.message)
    tracker.observe_frame(
        BDOFrame(second.index, second.message, second.context, next_sequence)
    )
    tracker.finalize_all()

    assert emitted[0].source == "Worker Production"
    chain = emitted[0].extra["deposit_origin_evidence"]["companion_chain"]
    assert chain["confirmed_family"] is True
    assert chain["confirmation"] == "unambiguous-bounded-window"


def test_worker_companions_survive_ten_distinct_storage_operations():
    emitted = []
    tracker = _tracker(emitted)
    delta, first, second = _worker_chain()
    tracker.observe_frame(delta)
    tracker.register(_storage_event(item_id=7002, seq=1000, message_length=80))

    next_sequence = 1080
    for index in range(10):
        token = bytes(range(0x20 + index * 8, 0x28 + index * 8))
        other_delta, _, _ = _worker_chain(
            delta_seq=next_sequence,
            token=token,
        )
        tracker.observe_frame(other_delta)
        tracker.register(
            _storage_event(
                item_id=15156 + index,
                quantity=1,
                seq=next_sequence,
                message_length=80,
            )
        )
        next_sequence += 80

    tracker.observe_frame(
        BDOFrame(first.index, first.message, first.context, next_sequence)
    )
    next_sequence += len(first.message)
    tracker.observe_frame(
        BDOFrame(second.index, second.message, second.context, next_sequence)
    )
    tracker.finalize_all()

    sources = {event.item_id: event.source for event in emitted}
    assert sources[7002] == "Worker Production"
    assert all(
        sources[15156 + index] is None for index in range(10)
    )


def test_stale_raw_stream_companions_do_not_revive_worker():
    emitted = []
    tracker = _tracker(emitted)
    delta, first, second = _worker_chain()
    tracker.observe_frame(delta)
    tracker.register(_storage_event(seq=1000, timestamp=1000.0, message_length=80))

    tracker.observe_stream(
        first.message + second.message,
        PacketContext(timestamp=1003.1, flow=FLOW, stream_start=1080),
    )

    assert emitted[0].source is None


def test_stale_second_companion_does_not_revive_worker():
    emitted = []
    tracker = _tracker(emitted)
    delta, first, second = _worker_chain()
    tracker.observe_frame(delta)
    tracker.register(_storage_event(seq=1000, timestamp=1000.0, message_length=80))
    tracker.observe_frame(
        BDOFrame(
            first.index,
            first.message,
            PacketContext(timestamp=1001.0, flow=FLOW),
            1080,
        )
    )
    tracker.observe_frame(
        BDOFrame(
            second.index,
            second.message,
            PacketContext(timestamp=1003.1, flow=FLOW),
            1138,
        )
    )

    assert emitted[0].source is None


def test_different_profile_storage_opcode_stops_companion_search():
    emitted = []
    tracker = DepositOriginTracker(
        decrement_specs=(),
        emit=emitted.append,
        storage_delta_opcodes=(0x2222,),
    )
    delta, next_delta, token_bearing_message = _worker_chain(first=0x2222)
    tracker.observe_frame(delta)
    tracker.register(_storage_event(seq=1000, message_length=80))

    tracker.observe_frame(next_delta)
    tracker.observe_frame(token_bearing_message)
    tracker.finalize_all()

    assert emitted[0].source is None


def test_runtime_confirmed_family_history_is_bounded():
    emitted = []
    tracker = _tracker(emitted)
    tracker.RUNTIME_CONFIRMED_FAMILY_LIMIT = 2
    families = [
        (0x1000 + index, 0x2000 + index, 0x3000 + index, 20, 30)
        for index in range(3)
    ]

    for family in families:
        tracker._confirm_family(family, "test")

    assert families[0] not in tracker._confirmed_companion_families
    assert set(families[1:]) <= tracker._confirmed_companion_families
    assert families[0] not in tracker._family_confirmation


@requires_fixtures
def test_july17_single_record_profile_decodes_full_worker_batch(tmp_path):
    try:
        fixture = fixture_path("multi_worker_deposit_4802_4003.pcapng")
    except FileNotFoundError:
        pytest.skip("July 17 private worker fixture not present")

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

    events = list(replay_pcap(fixture, opcode_profile=profile))

    assert [
        (event.item_id, event.quantity, event.record_index, event.source)
        for event in events
    ] == [
        (4802, 1, 1, "Worker Production"),
        (4003, 21, 2, "Worker Production"),
    ]


def test_stale_pending_deposit_flushes_as_unknown():
    emitted = []
    tracker = _tracker(emitted)
    tracker.observe_frame(_frame(0x0E6A, seq=1000, timestamp=1000.0))
    tracker.register(_storage_event(seq=1000, timestamp=1000.0))
    assert not emitted
    tracker.flush_stale(now=1005.0)
    assert emitted[0].source is None


def test_stale_flush_delivery_does_not_invert_tracker_and_session_locks():
    """A delivery callback must not retain a tracker dispatch lock.

    This recreates the former live-session AB-BA cycle deterministically:
    producer dispatch -> session delivery lock, while consumer delivery lock
    -> tracker stale flush.  Both pending events must still arrive in tracker
    order after the consumer releases its simulated session lock.
    """

    delivery_lock = RLock()
    callback_entered = ThreadEvent()
    consumer_holds_delivery = ThreadEvent()
    emitted = []
    thread_errors = []

    def deliver(event):
        try:
            callback_entered.set()
            assert consumer_holds_delivery.wait(timeout=2)
            with delivery_lock:
                emitted.append(event)
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            thread_errors.append(exc)

    tracker = DepositOriginTracker(
        decrement_specs=(DecrementSpec(0x1A32, 52, 42),),
        emit=deliver,
    )
    tracker.register(_storage_event(item_id=7002, seq=1000, timestamp=1000.0))
    tracker.register(_storage_event(item_id=7003, seq=2000, timestamp=1004.0))

    def producer_flush():
        try:
            # Only the first event is stale.  The consumer below queues the
            # second event while this thread owns dispatch and is paused in
            # the external callback.
            tracker.flush_stale(now=1003.0)
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            thread_errors.append(exc)

    def consumer_flush():
        try:
            with delivery_lock:
                consumer_holds_delivery.set()
                assert callback_entered.wait(timeout=2)
                tracker.flush_stale(now=1007.0)
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            thread_errors.append(exc)

    producer = Thread(target=producer_flush, daemon=True)
    consumer = Thread(target=consumer_flush, daemon=True)
    producer.start()
    assert callback_entered.wait(timeout=2)
    consumer.start()
    assert consumer_holds_delivery.wait(timeout=2)

    consumer.join(timeout=2)
    producer.join(timeout=2)

    assert not consumer.is_alive()
    assert not producer.is_alive()
    assert thread_errors == []
    assert [event.item_id for event in emitted] == [7002, 7003]


def test_stale_flush_serializes_a_concurrent_pending_registration():
    emitted = []
    tracker = _tracker(emitted)
    tracker.observe_frame(_frame(0x0E6A, seq=1000, timestamp=1000.0))
    tracker.register(_storage_event(item_id=7002, seq=1000, timestamp=1000.0))

    entered = ThreadEvent()
    release = ThreadEvent()
    registration_finished = ThreadEvent()
    thread_errors = []
    original_close = tracker._close_pending

    def paused_close(pending):
        entered.set()
        assert release.wait(timeout=2)
        original_close(pending)

    tracker._close_pending = paused_close

    def flush():
        try:
            tracker.flush_stale(now=1005.0)
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            thread_errors.append(exc)

    def register_second():
        try:
            tracker.register(
                _storage_event(item_id=7003, seq=2000, timestamp=1001.0)
            )
            registration_finished.set()
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            thread_errors.append(exc)

    flush_thread = Thread(target=flush)
    register_thread = Thread(target=register_second)
    flush_thread.start()
    assert entered.wait(timeout=2)
    register_thread.start()

    # Registration must wait for the stale-list replacement, otherwise the
    # older implementation overwrites the concurrent append with ``still``.
    assert not registration_finished.wait(timeout=0.05)
    release.set()
    flush_thread.join(timeout=2)
    register_thread.join(timeout=2)
    assert not flush_thread.is_alive()
    assert not register_thread.is_alive()
    assert thread_errors == []

    tracker._close_pending = original_close
    tracker.finalize_all()
    assert [event.item_id for event in emitted] == [7002, 7003]


def test_stale_flush_serializes_concurrent_neutral_batch_creation():
    emitted = []
    tracker = _tracker(emitted)

    def neutral(item_id, sequence, timestamp):
        return BDOEvent(
            event_type="storage_record",
            timestamp=timestamp,
            flow=Flow("10.0.0.1", 8889, "10.0.0.2", 50000),
            item_id=item_id,
            quantity=1,
            opcode=0x126D,
            message_length=479,
            record_offset=36,
            record_index=1,
            record_count=2,
            extra={"stream_sequence": sequence},
        )

    tracker.register(neutral(4802, 1000, 1000.0))
    entered = ThreadEvent()
    release = ThreadEvent()
    registration_finished = ThreadEvent()
    thread_errors = []
    original_emit_batch = tracker._emit_neutral_entries

    def paused_emit_batch(batch):
        entered.set()
        assert release.wait(timeout=2)
        original_emit_batch(batch)

    tracker._emit_neutral_entries = paused_emit_batch

    def flush():
        try:
            tracker.flush_stale(now=1005.0)
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            thread_errors.append(exc)

    def register_second():
        try:
            tracker.register(neutral(4003, 2000, 1001.0))
            registration_finished.set()
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            thread_errors.append(exc)

    flush_thread = Thread(target=flush)
    register_thread = Thread(target=register_second)
    flush_thread.start()
    assert entered.wait(timeout=2)
    register_thread.start()
    assert not registration_finished.wait(timeout=0.05)
    release.set()
    flush_thread.join(timeout=2)
    register_thread.join(timeout=2)
    assert thread_errors == []

    tracker._emit_neutral_entries = original_emit_batch
    tracker.finalize_all()
    assert [event.item_id for event in emitted] == [4802, 4003]


def test_lookahead_window_remains_hard_bounded():
    emitted = []
    tracker = _tracker(emitted)
    tracker.observe_frame(_frame(0x0E6A, seq=1000))
    tracker.register(_storage_event(seq=1000))
    for i in range(tracker.LOOKAHEAD_FRAMES):
        tracker.observe_frame(_frame(0x1CAE, seq=1100 + i))
    assert emitted and emitted[0].source is None


def test_pending_storage_operations_are_hard_bounded():
    emitted = []
    tracker = _tracker(emitted)
    tracker.MAX_PENDING_OPERATIONS_PER_FLOW = 2

    tracker.register(_storage_event(item_id=7001, seq=1000))
    tracker.register(_storage_event(item_id=7002, seq=2000))
    tracker.register(_storage_event(item_id=7003, seq=3000))

    assert [event.item_id for event in emitted] == [7001]
    assert [pending.event.item_id for pending in tracker._pending] == [7002, 7003]
    tracker.finalize_all()
    assert [event.item_id for event in emitted] == [7001, 7002, 7003]


@requires_fixtures
def test_classified_storage_sources_filter_through_the_canonical_field():
    # The dev-facing worker-tracker one-liner: filter at the API, applied
    # AFTER classification so the verdict is already on the event.
    manual = fixture_path("1000306_qty5_unstackable_i2s.pcapng")
    worker = fixture_path("worker_4607.pcapng")

    assert list(
        replay_pcap(
            manual,
            opcode_profile=JULY6_OPCODE_PROFILE,
            event_filter=EventFilter(sources={"Worker Production"}),
        )
    ) == []
    assert len(
        list(
            replay_pcap(
                manual,
                opcode_profile=JULY6_OPCODE_PROFILE,
                event_filter=EventFilter(sources={"Player Inventory"}),
            )
        )
    ) == 5

    events = list(
        replay_pcap(
            worker,
            opcode_profile=JULY6_OPCODE_PROFILE,
            event_filter=EventFilter(sources={"Worker Production"}),
        )
    )
    assert [(event.item_id, event.source) for event in events] == [
        (4607, "Worker Production")
    ]
