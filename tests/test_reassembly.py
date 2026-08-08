"""Focused regressions for TCP stream ordering and gap recovery."""

import pytest

from bdo_toolkit._engine import PacketEngine
from bdo_toolkit._framing import TargetMessageScanner
from bdo_toolkit._protocol import (
    GAP_RESET_SECONDS,
    MAX_PENDING_SEGMENTS,
    EventSpec,
    FlowKey,
)
from bdo_toolkit._reassembly import (
    _INITIAL_REORDER_GRACE_SECONDS,
    FlowManager,
)


_SPEC = EventSpec(
    label="LOOT_PREVIEW",
    opcode=0x1234,
    item_offset=23,
    quantity_offset=27,
    min_message_length=31,
)


def _target_frame(item_id: int = 7307, quantity: int = 8) -> bytes:
    message = bytearray(31)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = _SPEC.opcode.to_bytes(2, "little")
    message[_SPEC.item_offset : _SPEC.item_offset + 4] = item_id.to_bytes(
        4, "little"
    )
    message[
        _SPEC.quantity_offset : _SPEC.quantity_offset + 4
    ] = quantity.to_bytes(4, "little")
    return bytes(message)


def _segment(
    target,
    *,
    sequence: int,
    payload: bytes = b"",
    timestamp: float,
    syn: bool = False,
    fin: bool = False,
    destination_port: int = 50000,
) -> None:
    target.process_tcp_segment(
        source_ip="10.0.0.1",
        source_port=8889,
        destination_ip="10.0.0.2",
        destination_port=destination_port,
        sequence=sequence,
        payload=payload,
        timestamp=timestamp,
        syn=syn,
        fin=fin,
    )


class _RecordingScanner:
    def __init__(self) -> None:
        self.feeds: list[bytes] = []
        self.resets = 0

    def feed(self, data, _context):
        self.feeds.append(data)

    def scan_standalone(self, _data, _context):
        pass

    def reset(self):
        self.resets += 1


def test_consumer_can_raise_reorder_count_without_changing_default_policy():
    scanner = _RecordingScanner()
    manager = FlowManager(
        server_ports=(8889,),
        scanner_factory=lambda: scanner,
        max_pending_segments=256,
        max_pending_bytes=1_024,
    )
    expected = bytes(range(130))

    _segment(manager, sequence=99, timestamp=1.0, syn=True)
    for offset, value in enumerate(expected[1:], start=1):
        _segment(
            manager,
            sequence=100 + offset,
            payload=bytes((value,)),
            timestamp=1.0 + offset / 1_000,
        )

    # More than the generic 128-segment policy remains losslessly buffered for
    # this explicitly configured consumer until the missing head arrives.
    assert scanner.feeds == []
    _segment(
        manager,
        sequence=100,
        payload=expected[:1],
        timestamp=1.2,
    )

    assert b"".join(scanner.feeds) == expected
    assert scanner.resets == 0
    assert manager.tcp_gap_resets == 0


def test_default_reorder_count_policy_remains_unchanged():
    scanner = _RecordingScanner()
    manager = FlowManager(
        server_ports=(8889,),
        scanner_factory=lambda: scanner,
    )

    _segment(manager, sequence=99, timestamp=1.0, syn=True)
    for offset in range(1, MAX_PENDING_SEGMENTS + 2):
        _segment(
            manager,
            sequence=100 + offset,
            payload=b"x",
            timestamp=1.0 + offset / 1_000,
        )

    assert scanner.resets == 1
    assert manager.tcp_gap_resets == 1


def test_custom_reorder_byte_ceiling_still_resets_and_reports_loss():
    scanner = _RecordingScanner()
    manager = FlowManager(
        server_ports=(8889,),
        scanner_factory=lambda: scanner,
        max_pending_segments=256,
        max_pending_bytes=4,
    )

    _segment(manager, sequence=99, timestamp=1.0, syn=True)
    _segment(
        manager,
        sequence=101,
        payload=b"abc",
        timestamp=1.1,
    )
    _segment(
        manager,
        sequence=104,
        payload=b"def",
        timestamp=1.2,
    )

    assert b"".join(scanner.feeds) == b"abcdef"
    assert scanner.resets == 1
    assert manager.tcp_gap_resets == 1


def test_custom_reorder_byte_ceiling_is_restored_after_each_gap_resume():
    scanner = _RecordingScanner()
    manager = FlowManager(
        server_ports=(8889,),
        scanner_factory=lambda: scanner,
        max_pending_segments=256,
        max_pending_bytes=4,
    )

    _segment(manager, sequence=99, timestamp=1.0, syn=True)
    _segment(manager, sequence=101, payload=b"a", timestamp=1.1)
    _segment(manager, sequence=200, payload=b"b" * 100, timestamp=1.2)

    # Restarting at the earliest byte still leaves the later 100-byte segment
    # behind another gap. Capacity recovery must therefore continue instead
    # of retaining that segment above the configured four-byte ceiling.
    assert b"".join(scanner.feeds) == b"a" + (b"b" * 100)
    assert scanner.resets == 2
    assert manager.tcp_gap_resets == 2
    assert all(not state.pending for state in manager._flows.values())


@pytest.mark.parametrize(
    ("keyword", "value", "error"),
    (
        ("max_pending_segments", True, TypeError),
        ("max_pending_segments", 1.5, TypeError),
        ("max_pending_segments", 0, ValueError),
        ("max_pending_bytes", False, TypeError),
        ("max_pending_bytes", 1.5, TypeError),
        ("max_pending_bytes", 0, ValueError),
    ),
)
def test_reorder_capacity_configuration_is_validated(
    keyword: str,
    value: object,
    error: type[Exception],
):
    with pytest.raises(error):
        FlowManager(
            server_ports=(8889,),
            scanner_factory=_RecordingScanner,
            **{keyword: value},
        )


def test_wall_clock_service_releases_complete_frame_behind_idle_gap():
    events = []
    manager = FlowManager(
        server_ports=(8889,),
        scanner_factory=lambda: TargetMessageScanner(
            lambda event, _raw: events.append(event),
            (_SPEC,),
        ),
    )

    # Establish the stream at 1000, then leave ten captured bytes missing.
    _segment(manager, sequence=1000, payload=b"\xff" * 8, timestamp=10.0)
    _segment(
        manager,
        sequence=1018,
        payload=_target_frame(),
        timestamp=10.1,
    )
    assert events == []

    assert manager.service_gaps(10.1 + GAP_RESET_SECONDS - 0.01) == 0
    assert events == []

    # No later packet is needed: the caller's ordinary wall-clock tick is
    # enough to release the complete frame after the deadline.
    assert manager.service_gaps(10.1 + GAP_RESET_SECONDS + 0.01) == 1
    assert [(event.item_id, event.quantity) for event in events] == [(7307, 8)]
    assert manager.tcp_gap_resets == 1

    # The cumulative health count survives removal of the completed flow.
    _segment(manager, sequence=1049, timestamp=20.0, fin=True)
    assert manager.tcp_gap_resets == 1


@pytest.mark.parametrize("syn_sequence", [1000, 0xFFFFFFF8])
def test_empty_syn_anchor_reassembles_second_half_first_and_deduplicates(
    syn_sequence: int,
):
    events = []
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(_SPEC,),
        on_event=lambda event, _raw: events.append(event),
    )
    frame = _target_frame()
    split_at = 17
    payload_sequence = (syn_sequence + 1) & 0xFFFFFFFF

    # An observed empty SYN supplies the sequence anchor. The later half must
    # remain pending until the prefix arrives, even across uint32 wrap.
    _segment(
        engine,
        sequence=syn_sequence,
        timestamp=1.0,
        syn=True,
    )
    _segment(
        engine,
        sequence=(payload_sequence + split_at) & 0xFFFFFFFF,
        payload=frame[split_at:],
        timestamp=1.1,
    )
    assert events == []

    _segment(
        engine,
        sequence=payload_sequence,
        payload=frame[:split_at],
        timestamp=1.2,
    )
    assert [(event.item_id, event.quantity) for event in events] == [(7307, 8)]

    # A full retransmission is still inspected for a self-contained frame,
    # but PacketEngine's stream-sequence key suppresses the duplicate event.
    _segment(
        engine,
        sequence=payload_sequence,
        payload=frame,
        timestamp=1.3,
    )
    assert [(event.item_id, event.quantity) for event in events] == [(7307, 8)]


def test_missing_syn_proven_origin_commits_without_clock_service():
    events = []
    manager = FlowManager(
        server_ports=(8889,),
        scanner_factory=lambda: TargetMessageScanner(
            lambda event, _raw: events.append(event),
            (_SPEC,),
        ),
    )

    _segment(
        manager,
        sequence=1000,
        payload=_target_frame(),
        timestamp=1.0,
    )

    assert [(event.item_id, event.quantity) for event in events] == [(7307, 8)]


@pytest.mark.parametrize("payload_sequence", [1000, 0xFFFFFFF9])
def test_missing_syn_reassembles_second_half_first(payload_sequence: int):
    events = []
    frames = []
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(_SPEC,),
        on_event=lambda event, _raw: events.append(event),
        frame_observer=frames.append,
    )
    frame = _target_frame()
    split_at = 17

    # Capture attached after the handshake and the callback for the later TCP
    # segment raced ahead of its prefix.  The first bytes are provisional
    # until the lower sequence arrives, including across uint32 wrap.
    _segment(
        engine,
        sequence=(payload_sequence + split_at) & 0xFFFFFFFF,
        payload=frame[split_at:],
        timestamp=1.0,
    )
    assert events == []
    assert frames == []

    _segment(
        engine,
        sequence=payload_sequence,
        payload=frame[:split_at],
        timestamp=1.1,
    )

    assert [(event.item_id, event.quantity) for event in events] == [(7307, 8)]
    assert [collected.message for collected in frames] == [frame]
    assert frames[0].stream_sequence == payload_sequence


@pytest.mark.parametrize("payload_sequence", [1000, 0xFFFFFFF9])
@pytest.mark.parametrize(
    "boundaries,arrival_order",
    [
        ((0, 7, 18, 31), (1, 2, 0)),
        ((0, 6, 13, 22, 31), (2, 1, 3, 0)),
    ],
)
def test_missing_syn_retains_multiple_initial_reorders_until_head_arrives(
    payload_sequence: int,
    boundaries: tuple[int, ...],
    arrival_order: tuple[int, ...],
):
    events = []
    frames = []
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(_SPEC,),
        on_event=lambda event, _raw: events.append(event),
        frame_observer=frames.append,
    )
    frame = _target_frame()
    pieces = [
        frame[start:end]
        for start, end in zip(boundaries, boundaries[1:])
    ]

    for arrival_index, piece_index in enumerate(arrival_order):
        start = boundaries[piece_index]
        _segment(
            engine,
            sequence=(payload_sequence + start) & 0xFFFFFFFF,
            payload=pieces[piece_index],
            timestamp=1.0 + arrival_index * 0.01,
        )

    assert [(event.item_id, event.quantity) for event in events] == [(7307, 8)]
    assert [collected.message for collected in frames] == [frame]
    assert frames[0].stream_sequence == payload_sequence


@pytest.mark.parametrize("with_frame_observer", [False, True])
def test_observer_cannot_make_target_suffix_an_initial_anchor(
    with_frame_observer: bool,
):
    events = []
    frames = []
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(_SPEC,),
        on_event=lambda event, _raw: events.append(event),
        frame_observer=frames.append if with_frame_observer else None,
    )
    frame = _target_frame(item_id=0x00010008)
    split_at = 23

    # The suffix happens to begin with 08 00 and is eight bytes long. That is
    # weak generic-frame evidence, but an optional observer must not let it
    # become the primary stream anchor before the real target header arrives.
    _segment(
        engine,
        sequence=1000 + split_at,
        payload=frame[split_at:],
        timestamp=1.0,
    )
    _segment(
        engine,
        sequence=1000,
        payload=frame[:split_at],
        timestamp=1.1,
    )

    assert [(event.item_id, event.quantity) for event in events] == [
        (0x00010008, 8)
    ]
    if with_frame_observer:
        assert [collected.message for collected in frames] == [frame]


def test_missing_syn_initial_reorder_trims_overlapping_provisional_segments():
    events = []
    frames = []
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(_SPEC,),
        on_event=lambda event, _raw: events.append(event),
        frame_observer=frames.append,
    )
    frame = _target_frame()

    for start, end, timestamp in (
        (10, 23, 1.0),
        (18, 31, 1.1),
        (0, 14, 1.2),
    ):
        _segment(
            engine,
            sequence=1000 + start,
            payload=frame[start:end],
            timestamp=timestamp,
        )

    assert [(event.item_id, event.quantity) for event in events] == [(7307, 8)]
    assert [collected.message for collected in frames] == [frame]
    assert frames[0].stream_sequence == 1000


@pytest.mark.parametrize("payload_sequence", [1000, 0xFFFFFFF9])
def test_out_of_order_fin_waits_for_missing_initial_prefix(
    payload_sequence: int,
):
    events = []
    closed = []
    manager = FlowManager(
        server_ports=(8889,),
        scanner_factory=lambda: TargetMessageScanner(
            lambda event, _raw: events.append(event),
            (_SPEC,),
        ),
        on_flow_close=closed.append,
    )
    frame = _target_frame()
    split_at = 17

    _segment(
        manager,
        sequence=(payload_sequence + split_at) & 0xFFFFFFFF,
        payload=frame[split_at:],
        timestamp=1.0,
        fin=True,
    )
    assert events == []
    assert closed == []

    _segment(
        manager,
        sequence=payload_sequence,
        payload=frame[:split_at],
        timestamp=1.1,
    )

    assert [(event.item_id, event.quantity) for event in events] == [(7307, 8)]
    assert len(closed) == 1


def test_unproven_initial_segment_is_released_only_when_owner_services_clock():
    feeds = []

    class UnprovenScanner:
        def can_anchor_at_start(self, _data):
            return False

        def feed(self, data, context):
            feeds.append((data, context))

        def scan_standalone(self, _data, _context):
            pass

        def reset(self):
            pass

    manager = FlowManager(
        server_ports=(8889,),
        scanner_factory=UnprovenScanner,
    )
    payload = b"\xff\xfe\xfd"

    _segment(manager, sequence=1000, payload=payload, timestamp=10.0)
    assert feeds == []

    # FlowManager owns no timer thread. The grace expires only when its owning
    # root supplies a later clock value through service_gaps().
    assert (
        manager.service_gaps(
            10.0 + _INITIAL_REORDER_GRACE_SECONDS - 0.001
        )
        == 0
    )
    assert feeds == []

    assert (
        manager.service_gaps(
            10.0 + _INITIAL_REORDER_GRACE_SECONDS + 0.001
        )
        == 0
    )
    assert [(data, context.stream_start) for data, context in feeds] == [
        (payload, 1000)
    ]


def test_missing_syn_late_prefix_is_not_retroactively_joined_after_commit():
    events = []
    manager = FlowManager(
        server_ports=(8889,),
        scanner_factory=lambda: TargetMessageScanner(
            lambda event, _raw: events.append(event),
            (_SPEC,),
        ),
    )
    frame = _target_frame()
    split_at = 17

    _segment(
        manager,
        sequence=1000 + split_at,
        payload=frame[split_at:],
        timestamp=1.0,
    )
    manager.service_gaps(1.0 + _INITIAL_REORDER_GRACE_SECONDS + 0.001)

    # Commitment is one-way: this older prefix is inspected standalone and
    # cannot be joined to the suffix already delivered.
    _segment(
        manager,
        sequence=1000,
        payload=frame[:split_at],
        timestamp=1.3,
    )
    assert events == []

    # The chosen stream origin remains usable for later complete frames.
    _segment(
        manager,
        sequence=1000 + len(frame),
        payload=_target_frame(item_id=7308),
        timestamp=1.4,
    )
    assert [(event.item_id, event.quantity) for event in events] == [(7308, 8)]


def test_wall_clock_release_closes_deferred_fin_after_provisional_payload():
    feeds = []
    closed = []

    class UnprovenScanner:
        def can_anchor_at_start(self, _data):
            return False

        def feed(self, data, context):
            feeds.append((data, context))

        def scan_standalone(self, _data, _context):
            pass

        def reset(self):
            pass

    manager = FlowManager(
        server_ports=(8889,),
        scanner_factory=UnprovenScanner,
        on_flow_close=closed.append,
    )
    payload = b"\xff\xfe\xfd"

    _segment(
        manager,
        sequence=1000,
        payload=payload,
        timestamp=10.0,
        fin=True,
    )
    assert feeds == []
    assert closed == []

    manager.service_gaps(
        10.0 + _INITIAL_REORDER_GRACE_SECONDS + 0.001
    )

    assert [(data, context.stream_start) for data, context in feeds] == [
        (payload, 1000)
    ]
    assert len(closed) == 1


def test_wall_clock_closes_fin_only_gap_when_missing_bytes_never_arrive():
    feeds = []
    closed = []

    class RecordingScanner:
        def feed(self, data, context):
            feeds.append((data, context))

        def scan_standalone(self, _data, _context):
            pass

        def reset(self):
            pass

    manager = FlowManager(
        server_ports=(8889,),
        scanner_factory=RecordingScanner,
        on_flow_close=closed.append,
    )
    _segment(manager, sequence=99, timestamp=1.0, syn=True)
    _segment(manager, sequence=100, payload=b"0123456789", timestamp=1.1)
    _segment(manager, sequence=120, timestamp=1.2, fin=True)
    assert [data for data, _context in feeds] == [b"0123456789"]
    assert closed == []

    assert manager.service_gaps(1.2 + GAP_RESET_SECONDS - 0.001) == 0
    assert closed == []
    assert manager.service_gaps(1.2 + GAP_RESET_SECONDS + 0.001) == 1
    assert len(closed) == 1
    assert manager.tcp_gap_resets == 1

    # The completed state was removed; later clock service cannot close it a
    # second time or retain a dead flow indefinitely.
    manager.service_gaps(100.0)
    assert len(closed) == 1


def test_idle_and_capacity_removal_notify_flow_owner_without_false_loss_count():
    closed = []
    evictions = []
    manager = FlowManager(
        server_ports=(8889,),
        scanner_factory=lambda: TargetMessageScanner(lambda *_: None, (_SPEC,)),
        max_flows=1,
        idle_timeout=5.0,
        on_flow_close=closed.append,
        on_flow_eviction=lambda: evictions.append(True),
    )

    _segment(manager, sequence=100, timestamp=1.0, syn=True)
    first = FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000)
    assert manager.service_gaps(5.99) == 0
    assert closed == []

    assert manager.service_gaps(6.0) == 0
    assert closed == [first]
    assert evictions == []  # ordinary idle cleanup is not acquisition loss

    _segment(
        manager,
        sequence=200,
        timestamp=10.0,
        syn=True,
        destination_port=50001,
    )
    _segment(
        manager,
        sequence=300,
        timestamp=10.1,
        syn=True,
        destination_port=50002,
    )
    assert closed[-1] == FlowKey("10.0.0.1", 8889, "10.0.0.2", 50001)
    assert evictions == [True]
