"""Focused regressions for offset-free storage hydration classification."""

from __future__ import annotations

import dataclasses
import json

from bdo_toolkit import BDOEvent, EventFilter, Flow
from bdo_toolkit._protocol import (
    BDOFrame,
    CHARACTER_LOAD_CONTEXT,
    FlowKey,
    PacketContext,
    STORAGE_LOCATIONS,
)
from bdo_toolkit._storage_hydration import StorageHydrationTracker
from bdo_toolkit.capture import _EventCollector


FLOW = Flow(
    source_ip="203.0.113.10",
    source_port=8889,
    destination_ip="198.51.100.20",
    destination_port=51000,
)


def _inventory(timestamp: float) -> BDOEvent:
    return BDOEvent(
        event_type="inventory_snapshot",
        timestamp=timestamp,
        flow=FLOW,
        item_id=7003,
        quantity=1,
        opcode=0x1424,
    )


def _storage(
    timestamp: float,
    storage_id: int,
    *,
    opcode: int = 0x1C51,
    event_type: str = "storage_record",
    quantity: int = 1,
    record_count: int = 20,
    stream_sequence: int | None = None,
    storage_instance: str | None = None,
) -> BDOEvent:
    return BDOEvent(
        event_type=event_type,
        timestamp=timestamp,
        flow=FLOW,
        item_id=7000 + storage_id,
        quantity=quantity,
        opcode=opcode,
        message_length=270,
        record_count=record_count,
        storage_id=storage_id,
        storage_name=f"Town {storage_id}",
        storage_instance=storage_instance,
        extra=(
            {"stream_sequence": stream_sequence}
            if stream_sequence is not None
            else {}
        ),
    )


def test_live_event_splits_two_subthreshold_neutral_cohorts() -> None:
    emitted: list[BDOEvent] = []
    tracker = StorageHydrationTracker(emitted.append)

    tracker.observe_inventory(_inventory(10.0))
    for index in range(4):
        tracker.observe_storage(_storage(10.10 + index * 0.01, index + 1))

    live = _storage(
        10.15,
        99,
        event_type="storage_delta",
        quantity=5,
    )
    tracker.observe_storage(live)

    for index in range(4):
        tracker.observe_storage(_storage(10.20 + index * 0.01, index + 10))
    tracker.finalize_all()

    storage_events = [event for event in emitted if event.event_type != "inventory_snapshot"]
    assert [event.event_type for event in storage_events] == [
        "storage_record",
        "storage_record",
        "storage_record",
        "storage_record",
        "storage_delta",
        "storage_record",
        "storage_record",
        "storage_record",
        "storage_record",
    ]
    assert storage_events[4] is live
    assert not any(event.event_type == "storage_snapshot" for event in emitted)


def test_neutral_storage_opcodes_cannot_combine_into_one_hydration_cohort() -> None:
    emitted: list[BDOEvent] = []
    tracker = StorageHydrationTracker(emitted.append)

    tracker.observe_inventory(_inventory(20.0))
    for index in range(4):
        tracker.observe_storage(
            _storage(20.10 + index * 0.01, index + 1, opcode=0x1001)
        )
    for index in range(4):
        tracker.observe_storage(
            _storage(20.20 + index * 0.01, index + 10, opcode=0x1002)
        )
    tracker.finalize_all()

    storage_events = [event for event in emitted if event.event_type != "inventory_snapshot"]
    assert len(storage_events) == 8
    assert {event.event_type for event in storage_events} == {"storage_record"}


def test_delayed_older_live_event_does_not_clear_newer_inventory_anchor() -> None:
    emitted: list[BDOEvent] = []
    tracker = StorageHydrationTracker(emitted.append)

    tracker.observe_inventory(_inventory(30.0))
    tracker.observe_storage(
        _storage(29.5, 99, event_type="storage_delta", quantity=5)
    )
    for index in range(8):
        tracker.observe_storage(_storage(30.10 + index * 0.01, index + 1))
    tracker.finalize_all()

    snapshots = [event for event in emitted if event.event_type == "storage_snapshot"]
    assert len(snapshots) == 8
    assert {event.storage_id for event in snapshots} == set(range(1, 9))
    assert all(event.source is None for event in snapshots)


def test_five_town_unanchored_batch_remains_neutral_even_with_large_wrappers() -> None:
    emitted: list[BDOEvent] = []
    tracker = StorageHydrationTracker(emitted.append)

    for index in range(5):
        tracker.observe_storage(
            _storage(
                40.10 + index * 0.01,
                index + 1,
                record_count=72,
            )
        )
    tracker.finalize_all()

    assert len(emitted) == 5
    assert {event.event_type for event in emitted} == {"storage_record"}


def test_reused_four_tuple_does_not_inherit_another_flow_generation_anchor() -> None:
    emitted: list[BDOEvent] = []
    tracker = StorageHydrationTracker(emitted.append)

    tracker.observe_inventory(
        dataclasses.replace(_inventory(45.0), _flow_generation=1)
    )
    for index in range(8):
        tracker.observe_storage(
            dataclasses.replace(
                _storage(45.10 + index * 0.01, index + 1),
                _flow_generation=2,
            )
        )
    tracker.finalize_all()

    generation_two = [
        event
        for event in emitted
        if event._flow_generation == 2
    ]
    assert len(generation_two) == 8
    assert {event.event_type for event in generation_two} == {"storage_record"}


def test_stale_flush_and_flow_close_retire_pending_state_and_anchors() -> None:
    for retirement in ("stale", "flow-close"):
        emitted: list[BDOEvent] = []
        tracker = StorageHydrationTracker(emitted.append)
        tracker.observe_inventory(_inventory(50.0))
        emitted.clear()

        pending = _storage(50.1, 1)
        tracker.observe_storage(pending)
        assert emitted == [], retirement

        if retirement == "stale":
            next_timestamp = 50.0 + tracker.HYDRATION_EPOCH_SECONDS + 1.0
            tracker.flush_stale(next_timestamp)
        else:
            next_timestamp = 50.2
            tracker.close_flow(FLOW)

        assert emitted == [pending], retirement
        emitted.clear()

        # Neither lifecycle boundary may leave an inventory anchor behind.
        # Eight subsequent destinations therefore remain below the stronger
        # unanchored threshold and must stay neutral.
        for index in range(8):
            tracker.observe_storage(
                _storage(next_timestamp + 0.1 + index * 0.01, index + 10)
            )
        tracker.finalize_all()
        assert len(emitted) == 8, retirement
        assert {event.event_type for event in emitted} == {"storage_record"}


def test_unproven_hydration_pending_state_is_bounded_and_stays_neutral() -> None:
    emitted: list[BDOEvent] = []
    tracker = StorageHydrationTracker(emitted.append)
    tracker.MAX_PENDING_EVENTS = 2

    staged = tuple(_storage(60.0 + index * 0.01, 1) for index in range(3))
    for event in staged:
        tracker.observe_storage(event)

    assert emitted == list(staged)
    tracker.finalize_all()
    assert {event.event_type for event in emitted} == {"storage_record"}


def _write_origin_profile(tmp_path):
    profile = tmp_path / "origin-before-hydration.json"
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
                    "SOURCE_STACK_DECREMENT": [
                        {
                            "event": "SOURCE_STACK_DECREMENT",
                            "opcode": "0x1505",
                            "length": 47,
                            "quantity_removed_offset": 20,
                            "source_instance_offset": 30,
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
                },
            }
        ),
        encoding="utf-8",
    )
    return profile


def _inventory_wrapper() -> bytes:
    message = bytearray(255)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x1424).to_bytes(2, "little")
    message[5:7] = (1).to_bytes(2, "little")
    message[21:25] = CHARACTER_LOAD_CONTEXT
    message[34:38] = (7003).to_bytes(4, "little")
    message[38:42] = (1).to_bytes(4, "little")
    message[69:77] = bytes.fromhex("8877665544332211")
    return bytes(message)


def _storage_wrapper(storage_id: int, item_id: int) -> bytes:
    message = bytearray(270)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x1C51).to_bytes(2, "little")
    message[5:7] = (1).to_bytes(2, "little")
    message[8:12] = storage_id.to_bytes(4, "little")
    message[44:48] = item_id.to_bytes(4, "little")
    message[48:52] = (1).to_bytes(4, "little")
    message[79:87] = item_id.to_bytes(8, "little")
    return bytes(message)


def test_storage_id_filter_runs_after_hydration_cohort_promotion(tmp_path) -> None:
    storage_ids = tuple(STORAGE_LOCATIONS)[:8]
    selected_storage_id = storage_ids[3]
    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=EventFilter(
            event_types={"storage_snapshot"},
            storage_ids={selected_storage_id},
        ),
        opcode_profile=_write_origin_profile(tmp_path),
    )
    payload = _inventory_wrapper() + b"".join(
        _storage_wrapper(storage_id, 7100 + index)
        for index, storage_id in enumerate(storage_ids)
    )

    collector.engine.process_tcp_segment(
        source_ip=FLOW.source_ip,
        source_port=FLOW.source_port,
        destination_ip=FLOW.destination_ip,
        destination_port=FLOW.destination_port,
        sequence=1000,
        payload=payload,
        timestamp=70.0,
    )
    collector.engine.finish()
    collector.finalize()

    events = list(collector.drain_events())
    assert [(event.event_type, event.storage_id) for event in events] == [
        ("storage_snapshot", selected_storage_id)
    ]


def test_snapshot_only_filter_still_classifies_origin_before_hydration(tmp_path) -> None:
    """A manual eighth record must not complete a false snapshot cohort."""

    collector = _EventCollector(
        server_ports=(8889,),
        event_filter=EventFilter.snapshot_records(),
        opcode_profile=_write_origin_profile(tmp_path),
    )
    assert collector._tracker is not None

    collector._hydration.observe_inventory(_inventory(50.0))

    instance = bytes.fromhex("1122334455667788")
    decrement = bytearray(47)
    decrement[0:2] = len(decrement).to_bytes(2, "little")
    decrement[3:5] = (0x1505).to_bytes(2, "little")
    decrement[20:24] = (999).to_bytes(4, "little")
    decrement[30:38] = instance
    collector._tracker.observe_frame(
        BDOFrame(
            index=0,
            message=bytes(decrement),
            context=PacketContext(
                timestamp=49.9,
                flow=FlowKey(
                    source_ip=FLOW.source_ip,
                    source_port=FLOW.source_port,
                    destination_ip=FLOW.destination_ip,
                    destination_port=FLOW.destination_port,
                ),
            ),
            stream_sequence=1000,
        )
    )

    for index in range(7):
        collector._tracker.register(
            _storage(
                50.10 + index * 0.01,
                index + 1,
                quantity=index + 1,
                stream_sequence=2000 + index * 300,
            )
        )
    collector._tracker.register(
        _storage(
            50.18,
            8,
            quantity=999,
            stream_sequence=5000,
            storage_instance=f"0x{instance.hex()}",
        )
    )

    collector.finalize()
    events = list(collector.drain_events())

    # The seven unresolved records remain neutral and the eighth is proven
    # manual/live. The snapshot-only filter excludes both groups; only the
    # inventory anchor survives. If filtering bypassed origin classification,
    # all eight storage records would instead be promoted to false snapshots.
    assert [event.event_type for event in events] == ["inventory_snapshot"]
