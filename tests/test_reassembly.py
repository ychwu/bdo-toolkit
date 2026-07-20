"""Focused regressions for TCP stream ordering and gap recovery."""

import pytest

from bdo_toolkit._engine import PacketEngine
from bdo_toolkit._framing import TargetMessageScanner
from bdo_toolkit._protocol import GAP_RESET_SECONDS, EventSpec, FlowKey
from bdo_toolkit._reassembly import FlowManager


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
