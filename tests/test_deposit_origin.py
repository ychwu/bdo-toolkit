"""Deposit-origin classification: worker vs manual vs unknown.

Fixture tests lock the classifier to the labeled captures (including the
7002 ambient non-matching decrement and both storage-delta context modes);
synthetic tests pin the fail-closed rules that no capture currently
exercises.
"""

import json

import pytest

from fixture_paths import fixture_path, has_fixture_pcaps
from bdo_toolkit import EventFilter, replay_pcap
from bdo_toolkit.capture import _EventCollector
from bdo_toolkit._deposit_origin import DecrementSpec, DepositOriginTracker
from bdo_toolkit._engine import PacketEngine, toolkit_event_from_record
from bdo_toolkit._protocol import BDOFrame, EventSpec, FlowKey, PacketContext
from bdo_toolkit.events import BDOEvent, Flow
from bdo_toolkit.profiles import OriginCompanionFamily

requires_fixtures = pytest.mark.skipif(
    not has_fixture_pcaps(),
    reason="local pcap fixtures not present (private captures)",
)

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


def _origins(fixture):
    return [
        (event.deposit_origin, event.extra.get("deposit_origin_evidence"))
        for event in replay_pcap(fixture_path(fixture))
        if event.event_type == "storage_delta"
    ]


@requires_fixtures
@pytest.mark.parametrize("fixture", WORKER_FIXTURES)
def test_worker_deposits_classify_as_worker(fixture):
    results = _origins(fixture)
    assert results, f"no storage_delta events decoded from {fixture}"
    for origin, evidence in results:
        assert origin == "worker"
        assert evidence["worker_companions"] is True
        assert evidence["matching_decrement"] is False
        chain = evidence["companion_chain"]
        assert chain["detection"] == "shared-token-chain-v1"
        assert chain["known_family"] is False


@requires_fixtures
@pytest.mark.parametrize("fixture", MANUAL_FIXTURES)
def test_manual_deposits_classify_as_manual(fixture):
    results = _origins(fixture)
    assert results, f"no storage_delta events decoded from {fixture}"
    for origin, evidence in results:
        assert origin == "manual"
        assert evidence == {"worker_companions": False, "matching_decrement": True}


@requires_fixtures
def test_ambient_nonmatching_decrement_does_not_flip_worker_verdict():
    # 7002_qty25 has a 0x1A32 near the deposit that does NOT carry qty=25:
    # presence alone must not read as manual.
    (origin, evidence), = _origins("7002_qty25.pcapng")
    assert origin == "worker"
    assert evidence["matching_decrement"] is False


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
        extra={"stream_sequence": seq},
    )


def _worker_chain(delta_seq=1000, delta_opcode=0x0E6A, first=0x1558, second=0x1168):
    token = bytes.fromhex("07feabbfc91b8e00")
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

    assert emitted[0].deposit_origin == "unknown"
    assert emitted[0].extra["deposit_origin_evidence"]["matching_decrement"] is False


def test_no_evidence_yields_unknown():
    emitted = []
    tracker = _tracker(emitted)
    tracker.observe_frame(_frame(0x0E6A, seq=1000))
    tracker.register(_storage_event(seq=1000))
    tracker.finalize_all()
    assert emitted[0].deposit_origin == "unknown"


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
    assert emitted[0].deposit_origin == "worker"
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
    origins = [e.deposit_origin for e in emitted]
    assert origins == ["worker", "worker"]


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
    assert emitted and emitted[0].deposit_origin == "worker"


def test_worker_chain_survives_a_desynchronized_generic_frame_tap():
    """Raw stream correlation must work even when capture starts mid-frame."""
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
    delta_message[37:41] = (7002).to_bytes(4, "little")
    delta_message[41:45] = (25).to_bytes(4, "little")

    # 0x1000 is a plausible but incomplete leading length, deliberately
    # stalling the generic collector. The opcode scanner can still resync.
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

    assert tapped_frames == []
    assert emitted and emitted[0].deposit_origin == "worker"


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
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    return profile


def _july17_unknown_operation_storage(records):
    stride = 222
    message = bytearray(257 + (len(records) - 1) * stride)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x126D).to_bytes(2, "little")
    message[6] = 3  # unfamiliar operation discriminator
    message[7:15] = bytes.fromhex("3141592653589793")
    message[16:18] = len(records).to_bytes(2, "little")
    message[27:31] = (0x0020).to_bytes(4, "little")
    for index, (item_id, quantity) in enumerate(records):
        item_offset = 36 + index * stride
        message[item_offset : item_offset + 4] = item_id.to_bytes(4, "little")
        message[item_offset + 4 : item_offset + 8] = quantity.to_bytes(4, "little")
        message[item_offset + 12 : item_offset + 20] = b"\xff" * 8
        message[item_offset + 35 : item_offset + 43] = bytes([index + 1]) * 8
    return bytes(message)


def _july17_manual_decrement(quantity):
    message = bytearray(47)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x11AD).to_bytes(2, "little")
    message[27:31] = quantity.to_bytes(4, "little")
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
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=event_filter,
        opcode_profile=profile,
    )
    collector.engine.process_tcp_segment(
        source_ip=FLOW.source_ip,
        source_port=FLOW.source_port,
        destination_ip=FLOW.destination_ip,
        destination_port=FLOW.destination_port,
        sequence=1000,
        payload=payload,
        timestamp=1000.0,
    )
    collector.engine.finish()
    collector.finalize()
    return list(collector.drain_events())


def test_unknown_operation_manual_is_promoted_before_filtering(tmp_path):
    profile = _write_july17_unknown_operation_profile(tmp_path)
    storage = _july17_unknown_operation_storage(((7307, 8),))
    events = _collect_synthetic_current_storage(
        profile,
        _july17_manual_decrement(8) + storage,
        EventFilter(event_types={"storage_delta"}),
    )

    assert len(events) == 1
    event = events[0]
    assert (event.item_id, event.quantity, event.source) == (7307, 8, "Heidel")
    assert event.event_type == "storage_delta"
    assert event.storage_operation == "live"
    assert event.deposit_origin == "manual"
    assert event.extra["storage_delta"] == 8
    assert event.extra["deposit_origin_evidence"] == {
        "worker_companions": False,
        "matching_decrement": True,
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
    assert event.storage_operation == "unknown"
    assert event.deposit_origin is None
    assert "storage_delta" not in event.extra
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
        storage_operation="unknown",
        extra={"stream_sequence": 1000},
    )

    tracker.register(event)
    tracker.finalize_all()

    assert emitted == [event]
    assert emitted[0].deposit_origin is None


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
    assert {event.deposit_origin for event in events} == {"manual"}
    assert {event.storage_operation for event in events} == {"live"}
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
    assert event.storage_operation == "live"
    assert event.deposit_origin == "worker"
    assert event.extra["deposit_origin_evidence"]["matching_decrement"] is True
    assert event.extra["storage_operation_evidence"]["signal"] == (
        "worker_companions"
    )


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

    assert [event.deposit_origin for event in emitted] == ["worker", "worker"]
    assert len(observations) == 1
    assert observations[0].companion_opcodes == (0x0F7E, 0x0DE1)


def test_worker_companions_can_skip_three_unrelated_messages():
    emitted = []
    tracker = _tracker(emitted)
    delta, first, second = _worker_chain()
    tracker.observe_frame(delta)
    tracker.register(_storage_event(seq=1000, message_length=80))

    next_sequence = 1080
    for index in range(3):
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

    assert emitted[0].deposit_origin == "worker"
    chain = emitted[0].extra["deposit_origin_evidence"]["companion_chain"]
    assert chain["confirmed_family"] is True
    assert chain["confirmation"] == "unambiguous-bounded-window"


def test_next_storage_delta_stops_companion_search():
    emitted = []
    tracker = _tracker(emitted)
    delta, first, second = _worker_chain()
    tracker.observe_frame(delta)
    tracker.register(_storage_event(seq=1000, message_length=80))

    # Even token-bearing messages after this next storage operation belong to
    # that operation and must never be borrowed by the earlier delta.
    next_delta = BDOFrame(3, delta.message, delta.context, 1080)
    tracker.observe_frame(next_delta)
    tracker.observe_frame(BDOFrame(4, first.message, first.context, 1160))
    tracker.observe_frame(BDOFrame(5, second.message, second.context, 1218))
    tracker.finalize_all()

    assert emitted[0].deposit_origin == "unknown"


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

    assert emitted[0].deposit_origin == "unknown"


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


def test_known_family_generator_is_not_consumed_before_boundary_setup():
    family = OriginCompanionFamily(
        delta_opcode=0x0E6A,
        companion_opcodes=(0x1558, 0x1168),
        companion_lengths=(58, 23),
        detection="shared-token-chain-v1",
        observations=2,
        promoted_at=None,
    )
    tracker = DepositOriginTracker(
        decrement_specs=(),
        emit=lambda event: None,
        known_companion_families=(entry for entry in (family,)),
    )

    assert family.family_key in tracker._known_companion_families
    assert family.delta_opcode in tracker._storage_delta_opcodes


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
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    events = list(replay_pcap(fixture, opcode_profile=profile))

    assert [
        (event.item_id, event.quantity, event.record_index, event.deposit_origin)
        for event in events
    ] == [
        (4802, 1, 1, "worker"),
        (4003, 21, 2, "worker"),
    ]


def test_stale_pending_deposit_flushes_as_unknown():
    emitted = []
    tracker = _tracker(emitted)
    tracker.observe_frame(_frame(0x0E6A, seq=1000, timestamp=1000.0))
    tracker.register(_storage_event(seq=1000, timestamp=1000.0))
    assert not emitted
    tracker.flush_stale(now=1005.0)
    assert emitted[0].deposit_origin == "unknown"


def test_lookahead_window_expires_after_unrelated_frames():
    emitted = []
    tracker = _tracker(emitted)
    tracker.observe_frame(_frame(0x0E6A, seq=1000))
    tracker.register(_storage_event(seq=1000))
    for i in range(8):
        tracker.observe_frame(_frame(0x1CAE, seq=1100 + i))
    assert emitted and emitted[0].deposit_origin == "unknown"


@requires_fixtures
def test_format_human_shows_deposit_origin():
    events = list(replay_pcap(fixture_path("worker_4607.pcapng")))
    line = events[0].format_human()
    assert "deposit_origin=worker" in line


@requires_fixtures
def test_deposit_origins_filter_is_first_class():
    # The dev-facing worker-tracker one-liner: filter at the API, applied
    # AFTER classification so the verdict is already on the event.
    manual = fixture_path("1000306_qty5_unstackable_i2s.pcapng")
    worker = fixture_path("worker_4607.pcapng")

    assert list(
        replay_pcap(manual, event_filter=EventFilter(deposit_origins={"worker"}))
    ) == []
    assert len(
        list(replay_pcap(manual, event_filter=EventFilter(deposit_origins={"manual"})))
    ) == 5

    events = list(
        replay_pcap(worker, event_filter=EventFilter(deposit_origins={"worker"}))
    )
    assert [(e.item_id, e.deposit_origin) for e in events] == [(4607, "worker")]


def test_deposit_origin_defaults_to_none_off_storage_deltas():
    from bdo_toolkit.events import BDOEvent, Flow

    event = BDOEvent(
        event_type="item_received",
        timestamp=1000.0,
        flow=Flow("1.1.1.1", 8889, "2.2.2.2", 50000),
        item_id=7003,
        quantity=1,
    )
    assert event.deposit_origin is None
    assert "deposit_origin" not in event.to_dict()

    from bdo_toolkit.filters import EventFilter

    f = EventFilter.from_values(deposit_origins={"worker"})
    assert not f.allows(event)  # None never matches a set filter
