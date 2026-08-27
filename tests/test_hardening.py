"""Synthetic regressions for public API and transport hardening."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fixture_paths import JULY17_OPCODE_PROFILE

from bdo_toolkit import (
    BDOEvent,
    EventFilter,
    Flow,
    ProfileError,
    load_opcode_profile,
    replay_pcap,
)
from bdo_toolkit import _capture_backend as capture_backend_module
from bdo_toolkit import capture as capture_module
from bdo_toolkit._capture_backend import import_scapy
from bdo_toolkit._engine import PacketEngine
from bdo_toolkit._framing import TargetMessageScanner
from bdo_toolkit._protocol import BDOFrame, EventSpec, FlowKey, PacketContext
from bdo_toolkit._specs import event_specs_from_profile
from bdo_toolkit.calibration import (
    CalibrationAuthorityError,
    CalibrationRetention,
    CalibrationResult,
    DirectionMismatchError,
    MessageSpec,
    calibrate_frames,
    update_profile,
)
from bdo_toolkit import calibration as calibration_module


def _loot_preview_frame(item_id: int = 7003, quantity: int = 3) -> bytes:
    message = bytearray(244)
    message[0:2] = (244).to_bytes(2, "little")
    message[3:5] = (0x1643).to_bytes(2, "little")
    message[23:27] = item_id.to_bytes(4, "little")
    message[27:31] = quantity.to_bytes(4, "little")
    return bytes(message)


SYNTHETIC_EVENT_SPECS = (
    EventSpec(
        label="LOOT_PREVIEW",
        opcode=0x1643,
        item_offset=23,
        quantity_offset=27,
        min_message_length=31,
        default_context="Gathering",
    ),
    EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x0E6A,
        item_offset=37,
        quantity_offset=41,
        min_message_length=80,
        source_context_offset=8,
        record_count_offset=6,
        storage_instance_offset=72,
        repeat_stride=226,
        single_record_message_length=261,
        default_context="Storage",
    ),
)


def _engine(events: list) -> PacketEngine:
    return PacketEngine(
        server_ports=(8889,),
        event_specs=SYNTHETIC_EVENT_SPECS,
        on_event=lambda event, raw: events.append(event),
    )


def _segment(
    engine: PacketEngine,
    sequence: int,
    payload: bytes,
    *,
    fin: bool = False,
    syn: bool = False,
) -> None:
    engine.process_tcp_segment(
        source_ip="203.0.113.1",
        source_port=8889,
        destination_ip="198.51.100.2",
        destination_port=50000,
        sequence=sequence,
        payload=payload,
        timestamp=1000.0,
        fin=fin,
        syn=syn,
    )


def _storage_frame(
    *,
    opcode: int = 0x9999,
    item_id: int = 99123,
    quantity: int = 3,
    count: int = 1,
    index: int = 0,
    contradictory: bool = False,
) -> BDOFrame:
    stride = 226
    length = 261 + (count - 1) * stride
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = opcode.to_bytes(2, "little")
    message[6:8] = count.to_bytes(2, "little")
    message[8:12] = bytes.fromhex("20000000")
    if contradictory:
        message[20:24] = bytes.fromhex("d0f205a3")
    for record_index in range(count):
        offset = 37 + record_index * stride
        message[offset : offset + 4] = (item_id + record_index).to_bytes(4, "little")
        message[offset + 4 : offset + 8] = (
            quantity if record_index == 0 else 1
        ).to_bytes(4, "little")
        message[offset + 12 : offset + 20] = b"\xff" * 8
        message[offset + 35 : offset + 43] = (record_index + 1).to_bytes(8, "little")
    return BDOFrame(
        index=index,
        message=bytes(message),
        context=PacketContext(
            timestamp=1000.0 + index / 100,
            flow=FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000),
        ),
        stream_sequence=100 + index,
    )


def test_replay_yields_before_processing_the_next_packet(monkeypatch):
    progress: list[str] = []

    def fake_iter(path: Path, engine: PacketEngine):
        _segment(engine, 1000, _loot_preview_frame(7003, 1))
        progress.append("first")
        yield None
        progress.append("second")
        _segment(engine, 2000, _loot_preview_frame(7004, 1))
        yield None
        engine.finish()

    monkeypatch.setattr(capture_module, "iter_pcap_file", fake_iter)
    events = replay_pcap(
        "unused.pcapng", opcode_profile=JULY17_OPCODE_PROFILE
    )
    assert next(events).item_id == 7003
    assert progress == ["first"]
    events.close()


def test_callback_collector_does_not_retain_delivered_events():
    delivered: list[BDOEvent] = []
    collector = capture_module._EventCollector(
        server_ports=(8889,),
        opcode_profile=JULY17_OPCODE_PROFILE,
        on_event=delivered.append,
    )
    event = BDOEvent("test", 0.0, Flow("a", 1, "b", 2), 1, 1)

    collector._deliver(event)

    assert delivered == [event]
    assert list(collector.drain_events()) == []


def test_fin_drains_a_complete_segment_pending_after_a_gap():
    events: list = []
    engine = _engine(events)
    _segment(engine, 1000, b"prefix")
    _segment(engine, 2000, _loot_preview_frame(), fin=True)
    engine.finish()

    assert [(event.item_id, event.quantity) for event in events] == [(7003, 3)]


def test_fragmented_frame_reassembles_across_tcp_sequence_wrap():
    events: list = []
    engine = _engine(events)
    message = _loot_preview_frame()
    _segment(engine, 0xFFFFFFF0, message[:16])
    _segment(engine, 0, message[16:])
    engine.finish()

    assert [(event.item_id, event.quantity) for event in events] == [(7003, 3)]


def test_syn_sequence_number_is_consumed_before_payload():
    events: list = []
    engine = _engine(events)
    message = _loot_preview_frame()
    _segment(engine, 1000, message[:10], syn=True)
    _segment(engine, 1011, message[10:])
    engine.finish()

    assert len(events) == 1


def test_storage_batch_above_old_4096_byte_limit_decodes_all_records():
    count = 18
    length = 35 + 226 * count
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = (0x0E6A).to_bytes(2, "little")
    message[6:8] = count.to_bytes(2, "little")
    message[8:12] = bytes.fromhex("20000000")
    for index in range(count):
        offset = 37 + 226 * index
        message[offset : offset + 4] = (7003 + index).to_bytes(4, "little")
        message[offset + 4 : offset + 8] = (1).to_bytes(4, "little")
        message[offset + 35 : offset + 43] = (index + 1).to_bytes(8, "little")

    events: list = []
    engine = _engine(events)
    _segment(engine, 1, bytes(message))
    engine.finish()

    assert len(events) == count


def test_invalid_capture_is_value_error_and_does_not_remain_locked(tmp_path):
    capture = tmp_path / "invalid.pcapng"
    capture.write_bytes(b"not a capture")

    with pytest.raises(ValueError, match="Could not read capture"):
        list(replay_pcap(capture, opcode_profile=JULY17_OPCODE_PROFILE))

    capture.unlink()
    assert not capture.exists()


@pytest.mark.parametrize("error_type", [OSError, ValueError])
def test_iter_pcap_file_preserves_consumer_exception_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    error_type: type[Exception],
) -> None:
    capture = tmp_path / "synthetic-valid.pcapng"
    capture.write_bytes(b"reader input is supplied by the deterministic fake")
    expected = error_type("consumer sentinel")

    class FakeReader:
        def __init__(self, _source: object) -> None:
            self.closed = False
            self._packets = iter((object(),))
            readers.append(self)

        def __iter__(self) -> FakeReader:
            return self

        def __next__(self) -> object:
            return next(self._packets)

        def close(self) -> None:
            self.closed = True

    readers: list[FakeReader] = []

    class FakeEngine:
        def finish(self) -> None:
            raise AssertionError("failed consumer replay must not be finalized")

    def fail_consumer(_engine: object):
        def handle(_packet: object) -> None:
            raise expected

        return handle

    monkeypatch.setattr(
        capture_backend_module,
        "import_scapy",
        lambda: (object(), object(), object(), object(), FakeReader),
    )
    monkeypatch.setattr(capture_backend_module, "make_packet_handler", fail_consumer)

    with pytest.raises(error_type) as raised:
        list(capture_backend_module.iter_pcap_file(capture, FakeEngine()))

    assert raised.value is expected
    assert len(readers) == 1
    assert readers[0].closed


def test_import_scapy_does_not_mutate_global_ipv6_setting():
    from scapy.config import conf

    previous = conf.ipv6_enabled
    try:
        conf.ipv6_enabled = True
        import_scapy()
        assert conf.ipv6_enabled is True
    finally:
        conf.ipv6_enabled = previous


def test_explicit_calibration_refuses_contradictory_intrinsics():
    frame = _storage_frame(contradictory=True)

    with pytest.raises(DirectionMismatchError, match="contradictory"):
        calibrate_frames(
            [frame],
            item_id=99123,
            quantity=3,
            action="inventory-to-storage",
        )


def test_storage_count_authority_requires_two_distinct_validated_shapes():
    single = _storage_frame()
    multi = _storage_frame(count=2, index=1)

    assert "CalibrationAuthorityError" in calibration_module.__all__
    for frames in ([single], [multi]):
        with pytest.raises(
            CalibrationAuthorityError,
            match="record-count-field",
        ):
            calibrate_frames(
                frames,
                item_id=99123,
                quantity=3,
                action="inventory-to-storage",
            )

    result = calibrate_frames(
        [single, multi],
        item_id=99123,
        quantity=3,
        action="inventory-to-storage",
    )
    delta = next(spec for spec in result.specs if spec.event == "STORAGE_ITEM_DELTA")
    assert delta.record_count_offset == 6


def test_post_patch_storage_profile_keeps_context_and_stride(tmp_path):
    frame = _storage_frame(opcode=0x9999)
    count_authority = _storage_frame(
        opcode=0x9999,
        item_id=88123,
        count=2,
        index=1,
    )
    result = calibrate_frames(
        [frame, count_authority],
        item_id=99123,
        quantity=3,
        action="inventory-to-storage",
    )
    delta = next(spec for spec in result.specs if spec.event == "STORAGE_ITEM_DELTA")

    assert delta.context_offset == 8
    assert delta.record_count_offset == 6
    assert delta.repeat_stride == 226

    profile_path = tmp_path / "nested" / "opcodes.json"
    update_profile(result, profile_path, action="inventory-to-storage")
    loaded = event_specs_from_profile(load_opcode_profile(profile_path))
    decode_spec = next(spec for spec in loaded.specs if spec.opcode == 0x9999)
    assert decode_spec.source_context_offset == 8
    assert decode_spec.record_count_offset == 6
    assert decode_spec.repeat_stride == 226

    message = bytearray(487)
    message[0:2] = (487).to_bytes(2, "little")
    message[3:5] = (0x9999).to_bytes(2, "little")
    message[6:8] = (2).to_bytes(2, "little")
    message[8:12] = bytes.fromhex("20000000")
    for index, item_id in enumerate((99123, 99124)):
        offset = 37 + 226 * index
        message[offset : offset + 4] = item_id.to_bytes(4, "little")
        message[offset + 4 : offset + 8] = (1).to_bytes(4, "little")
        message[offset + 35 : offset + 43] = (index + 1).to_bytes(8, "little")
    decoded: list = []
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=loaded.specs,
        on_event=lambda event, raw: decoded.append(event),
    )
    _segment(engine, 1, bytes(message))
    engine.finish()
    assert [event.item_id for event in decoded] == [99123, 99124]


def test_post_patch_profile_uses_its_own_single_record_lengths(tmp_path):
    """A patch may change wrapper bytes without changing record offsets/stride."""
    profile_path = tmp_path / "opcodes.local"
    update_profile(
        [
            MessageSpec(
                event="INVENTORY_TRANSFER",
                opcode=0x1AAE,
                length=254,
                item_id_offset=33,
                quantity_offset=37,
                item_instance_offset=68,
                context_offset=24,
                repeat_stride=228,
            ),
            MessageSpec(
                event="STORAGE_ITEM_DELTA",
                opcode=0x0D7E,
                length=258,
                item_id_offset=37,
                quantity_added_offset=41,
                destination_instance_offset=72,
                context_offset=8,
                record_count_offset=6,
            ),
        ],
        profile_path,
        backup=False,
    )
    loaded = event_specs_from_profile(load_opcode_profile(profile_path))
    by_label = {spec.label: spec for spec in loaded.specs}

    assert by_label["INVENTORY_TRANSFER"].single_record_message_length == 254
    assert by_label["INVENTORY_TO_STORAGE"].repeat_stride is None
    assert by_label["INVENTORY_TO_STORAGE"].single_record_message_length == 258

    inventory = bytearray(254)
    inventory[0:2] = (254).to_bytes(2, "little")
    inventory[3:5] = (0x1AAE).to_bytes(2, "little")
    inventory[24:28] = bytes.fromhex("d0f205a3")
    inventory[33:37] = (7003).to_bytes(4, "little")
    inventory[37:41] = (5).to_bytes(4, "little")
    inventory[68:76] = b"\x11" * 8

    storage = bytearray(258)
    storage[0:2] = (258).to_bytes(2, "little")
    storage[3:5] = (0x0D7E).to_bytes(2, "little")
    storage[6:8] = (1).to_bytes(2, "little")
    storage[8:12] = bytes.fromhex("05000000")
    storage[37:41] = (7003).to_bytes(4, "little")
    storage[41:45] = (5).to_bytes(4, "little")
    storage[72:80] = b"\x22" * 8

    decoded: list = []
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=loaded.specs,
        on_event=lambda event, raw: decoded.append(event),
    )
    _segment(engine, 1, bytes(inventory) + bytes(storage))
    engine.finish()

    assert [(event.label, event.item_id, event.quantity) for event in decoded] == [
        ("INVENTORY_TRANSFER", 7003, 5),
        ("INVENTORY_TO_STORAGE", 7003, 5),
    ]


def _july17_structural_batch() -> bytes:
    message = bytearray(479)
    message[0:2] = (479).to_bytes(2, "little")
    message[3:5] = (0x126D).to_bytes(2, "little")
    message[6] = 1
    message[7:15] = b"\x31\x41\x59\x26\x53\x58\x97\x93"
    message[16:18] = (2).to_bytes(2, "little")
    message[27:31] = bytes.fromhex("20000000")
    for offset, item_id, quantity, instance_byte in (
        (36, 4802, 1, b"\x11"),
        (258, 4003, 21, b"\x22"),
    ):
        message[offset : offset + 4] = item_id.to_bytes(4, "little")
        message[offset + 4 : offset + 8] = quantity.to_bytes(4, "little")
        message[offset + 12 : offset + 20] = b"\xff" * 8
        message[offset + 35 : offset + 43] = instance_byte * 8
    return bytes(message)


@pytest.mark.parametrize("saved_stride", [None, 221])
def test_runtime_derives_changed_batch_stride_from_records(saved_stride):
    """A single-record profile must decode a later batch and stale stride."""
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
        source_context_offset=27,
        record_count_offset=16,
        storage_instance_offset=71,
        repeat_stride=saved_stride,
        single_record_message_length=257,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(engine, 1, _july17_structural_batch())
    engine.finish()

    assert [
        (event.item_id, event.quantity, event.record_index, event.record_count)
        for event in decoded
    ] == [
        (4802, 1, 1, 2),
        (4003, 21, 2, 2),
    ]
    assert {event.storage_id for event in decoded} == {0x20}
    assert {event.storage_operation for event in decoded} == {"unknown"}


def test_declared_batch_with_invalid_record_instance_fails_closed():
    message = bytearray(_july17_structural_batch())
    # A valid declaration must not allow a corrupt record to be skipped while
    # the remaining records are emitted as a partial batch.
    message[258 + 35 : 258 + 43] = b"\x00" * 8
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
        source_context_offset=27,
        record_count_offset=16,
        storage_instance_offset=71,
        single_record_message_length=257,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(engine, 1, bytes(message))
    engine.finish()

    assert decoded == []


def test_current_wrapper_cannot_fall_back_after_count_geometry_conflicts():
    message = bytearray(_july17_structural_batch())
    # Both records still have the legacy marker. A contradictory declaration
    # must invalidate this current-wrapper frame instead of bypassing the
    # count check through marker recovery.
    message[16:18] = (3).to_bytes(2, "little")
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
        source_context_offset=27,
        record_count_offset=16,
        storage_instance_offset=71,
        single_record_message_length=257,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(engine, 1, bytes(message))
    engine.finish()

    assert decoded == []


def test_current_wrapper_preserves_unfamiliar_operation_mode_as_unknown():
    message = bytearray(_july17_structural_batch())
    message[6] = 3
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
        source_context_offset=27,
        record_count_offset=16,
        storage_instance_offset=71,
        single_record_message_length=257,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(engine, 1, bytes(message))
    engine.finish()

    assert len(decoded) == 2
    assert {event.storage_operation for event in decoded} == {"unknown"}


def test_storage_profile_without_count_authority_fails_closed():
    message = bytearray(261)
    message[0:2] = (261).to_bytes(2, "little")
    message[3:5] = (0x0E6A).to_bytes(2, "little")
    message[28:32] = (0x0020).to_bytes(4, "little")
    message[37:41] = (7003).to_bytes(4, "little")
    message[41:45] = (3).to_bytes(4, "little")
    message[45:57] = b"\x00" * 4 + b"\xff" * 8
    message[72:80] = b"\x22" * 8
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x0E6A,
        item_offset=37,
        quantity_offset=41,
        min_message_length=261,
        source_context_offset=28,
        storage_instance_offset=72,
        single_record_message_length=261,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(engine, 1, bytes(message))
    engine.finish()

    assert decoded == []


def _july17_arehaza_snapshot() -> bytes:
    count = 25
    stride = 222
    length = 35 + count * stride
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = (0x126D).to_bytes(2, "little")
    message[6] = 2
    message[16:18] = count.to_bytes(2, "little")
    message[27:31] = (0x02B5).to_bytes(4, "little")

    item_ids = [11, 13, 14, *range(7003, 7025)]
    non_marker_values = (
        bytes.fromhex("5f70f36400000000"),
        bytes.fromhex("1e9a866500000000"),
        bytes.fromhex("b47f926500000000"),
    )
    for index, item_id in enumerate(item_ids):
        offset = 36 + stride * index
        message[offset : offset + 4] = item_id.to_bytes(4, "little")
        message[offset + 4 : offset + 8] = (1).to_bytes(4, "little")
        message[offset + 12 : offset + 20] = (
            non_marker_values[index] if index < 3 else b"\xff" * 8
        )
        message[offset + 35 : offset + 43] = (index + 1).to_bytes(8, "little")
    return bytes(message)


def test_declared_count_decodes_arehaza_records_without_marker():
    """The first three real Arehaza item types do not carry the FF marker."""
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
        source_context_offset=27,
        record_count_offset=16,
        storage_instance_offset=71,
        single_record_message_length=257,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(engine, 1, _july17_arehaza_snapshot())
    engine.finish()

    assert len(decoded) == 25
    assert [event.item_id for event in decoded[:4]] == [11, 13, 14, 7003]
    assert decoded[0].record_index == 1
    assert decoded[-1].record_index == decoded[-1].record_count == 25
    assert {event.storage_id for event in decoded} == {0x02B5}
    assert {event.storage_operation for event in decoded} == {"unknown"}


def test_declared_count_length_mismatch_fails_closed_without_markers():
    message = bytearray(_july17_arehaza_snapshot())
    message[16:18] = (24).to_bytes(2, "little")
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
        source_context_offset=27,
        record_count_offset=16,
        storage_instance_offset=71,
        single_record_message_length=257,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(engine, 1, bytes(message))
    engine.finish()

    assert decoded == []


def _august7_storage_wrapper(
    *,
    mode: int,
    token: bytes,
    storage_id: int = 0x0020,
    count: int = 2,
) -> bytes:
    stride = 228
    base_length = 270
    length = base_length + (count - 1) * stride
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = (0x1C51).to_bytes(2, "little")
    message[5:7] = count.to_bytes(2, "little")
    message[8:12] = storage_id.to_bytes(4, "little")
    message[31:39] = token
    message[39] = mode
    for index in range(count):
        offset = 44 + stride * index
        message[offset : offset + 4] = (7003 + index).to_bytes(4, "little")
        message[offset + 4 : offset + 8] = (index + 1).to_bytes(4, "little")
        # Deliberately omit the legacy FF marker: declared count geometry must
        # prove every record without relying on an item-type-specific pattern.
        message[offset + 35 : offset + 43] = (index + 1).to_bytes(8, "little")
    return bytes(message)


@pytest.mark.parametrize(
    ("mode", "token"),
    (
        (2, b"\x00" * 8),
        (1, bytes.fromhex("1122334455667788")),
        (0, b"\x00" * 8),
    ),
)
def test_august_storage_layout_decodes_dynamic_count_and_destination(
    mode,
    token,
):
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x1C51,
        item_offset=44,
        quantity_offset=48,
        min_message_length=270,
        source_context_offset=8,
        record_count_offset=5,
        storage_instance_offset=79,
        single_record_message_length=270,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(
        engine,
        1,
        _august7_storage_wrapper(mode=mode, token=token),
    )
    engine.finish()

    assert [event.item_id for event in decoded] == [7003, 7004]
    assert [event.record_index for event in decoded] == [1, 2]
    assert {event.record_count for event in decoded} == {2}
    assert {event.storage_id for event in decoded} == {0x0020}
    assert {event.storage_operation for event in decoded} == {"unknown"}


def test_august_snapshot_count_conflict_fails_closed_without_marker_fallback():
    message = bytearray(
        _august7_storage_wrapper(mode=2, token=b"\x00" * 8, count=2)
    )
    message[5:7] = (3).to_bytes(2, "little")
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x1C51,
        item_offset=44,
        quantity_offset=48,
        min_message_length=270,
        source_context_offset=8,
        record_count_offset=5,
        storage_instance_offset=79,
        single_record_message_length=270,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(engine, 1, bytes(message))
    engine.finish()

    assert decoded == []


def test_calibration_discovers_changed_context_and_mixed_batch_stride(tmp_path):
    message = bytearray(479)
    message[0:2] = (479).to_bytes(2, "little")
    message[3:5] = (0x0D7E).to_bytes(2, "little")
    message[25:29] = bytes.fromhex("20000000")
    message[35:37] = (2).to_bytes(2, "little")
    for offset, item_id, quantity, instance_byte in (
        (37, 5004, 6, b"\x11"),
        (258, 4604, 25, b"\x22"),
    ):
        message[offset : offset + 4] = item_id.to_bytes(4, "little")
        message[offset + 4 : offset + 8] = quantity.to_bytes(4, "little")
        message[offset + 12 : offset + 20] = b"\xff" * 8
        message[offset + 35 : offset + 43] = instance_byte * 8
    frame = BDOFrame(
        index=0,
        message=bytes(message),
        context=PacketContext(
            timestamp=1000.0,
            flow=FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000),
        ),
        stream_sequence=100,
    )

    single_message = bytearray(258)
    single_message[0:2] = (258).to_bytes(2, "little")
    single_message[3:5] = (0x0D7E).to_bytes(2, "little")
    single_message[25:29] = bytes.fromhex("20000000")
    single_message[35:37] = (1).to_bytes(2, "little")
    single_message[37:41] = (5004).to_bytes(4, "little")
    single_message[41:45] = (6).to_bytes(4, "little")
    single_message[49:57] = b"\xff" * 8
    single_message[72:80] = b"\x33" * 8
    single_frame = BDOFrame(
        index=1,
        message=bytes(single_message),
        context=PacketContext(
            timestamp=1000.1,
            flow=frame.context.flow,
        ),
        stream_sequence=101,
    )

    result = calibrate_frames(
        [frame, single_frame],
        item_id=5004,
        quantity=6,
        action="inventory-to-storage",
    )
    delta = next(spec for spec in result.specs if spec.event == "STORAGE_ITEM_DELTA")

    assert delta.length == 258
    assert delta.context_offset == 25
    assert delta.record_count_offset == 35
    assert delta.repeat_stride == 221

    # Watching the SECOND item in the same mixed batch must still write a
    # first-record profile rather than pinning offsets to record 2.
    second_result = calibrate_frames(
        [frame, single_frame],
        item_id=4604,
        quantity=25,
        action="inventory-to-storage",
    )
    second_delta = next(
        spec for spec in second_result.specs if spec.event == "STORAGE_ITEM_DELTA"
    )
    assert (
        second_delta.length,
        second_delta.item_id_offset,
        second_delta.quantity_added_offset,
        second_delta.destination_instance_offset,
        second_delta.repeat_stride,
    ) == (258, 37, 41, 72, 221)

    profile_path = tmp_path / "opcodes.local"
    update_profile(
        result,
        profile_path,
        action="inventory-to-storage",
        backup=False,
    )
    loaded = event_specs_from_profile(load_opcode_profile(profile_path))
    decoded: list = []
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=loaded.specs,
        on_event=lambda event, raw: decoded.append(event),
    )
    _segment(engine, 1, bytes(message))
    engine.finish()

    assert [(event.item_id, event.quantity) for event in decoded] == [
        (5004, 6),
        (4604, 25),
    ]


def test_growing_reference_frame_is_persisted():
    record = _storage_frame()
    count_authority = _storage_frame(item_id=88123, count=2, index=2)
    reference_message = bytearray(54)
    reference_message[0:2] = (54).to_bytes(2, "little")
    reference_message[3:5] = (0x1234).to_bytes(2, "little")
    reference_message[10:14] = (99123).to_bytes(4, "little")
    reference = BDOFrame(
        index=1,
        message=bytes(reference_message),
        context=PacketContext(999.0, record.context.flow),
        stream_sequence=1,
    )

    result = calibrate_frames(
        [reference, record, count_authority],
        item_id=99123,
        quantity=3,
        action="inventory-to-storage",
    )

    source_ref = next(
        spec for spec in result.specs if spec.event == "SOURCE_ITEM_REFERENCE"
    )
    assert source_ref.length == 54
    assert source_ref.item_id_offset == 10


def test_missing_explicit_profile_does_not_silently_fall_back(tmp_path):
    events = replay_pcap(
        tmp_path / "capture.pcapng",
        opcode_profile=tmp_path / "typo.json",
    )
    with pytest.raises(FileNotFoundError, match="Opcode profile"):
        next(events)


def test_inactive_explicit_profile_fails_instead_of_mixing_authorities(tmp_path):
    profile_path = tmp_path / "inactive.json"
    profile_path.write_text(
        json.dumps({"version": 1, "profile_active": False, "specs": {}}),
        encoding="utf-8",
    )

    assert load_opcode_profile(profile_path).active is False
    events = replay_pcap("unused.pcapng", opcode_profile=profile_path)
    with pytest.raises(ProfileError, match="inactive"):
        next(events)


def test_origin_observer_keeps_origin_graph_for_nonstorage_filter():
    collector = capture_module._EventCollector(
        server_ports=(8889,),
        opcode_profile=JULY17_OPCODE_PROFILE,
        event_filter=EventFilter(event_types={"item_received"}),
        origin_observer=lambda _observation: None,
    )

    assert collector._tracker is not None


def test_empty_profile_update_is_a_true_noop(tmp_path):
    path = tmp_path / "opcodes.json"
    original = '{"sentinel": true}\n'
    path.write_text(original, encoding="utf-8")

    update = update_profile(
        CalibrationResult(
            (),
            (),
            0,
            retention=CalibrationRetention(0, 0, 0, 0, 0, 0),
        ),
        path,
    )

    assert not update.written
    assert update.backup_path is None
    assert path.read_text(encoding="utf-8") == original


def test_partial_auto_calibration_cannot_preserve_stale_storage_silently(tmp_path):
    path = tmp_path / "opcodes.json"
    original = json.dumps(
        {
            "version": 1,
            "profile_active": True,
            "specs": {
                "STORAGE_ITEM_DELTA": [
                    {
                        "event": "STORAGE_ITEM_DELTA",
                        "opcode": "0x0E6A",
                        "length": 261,
                        "item_id_offset": 37,
                        "quantity_added_offset": 41,
                        "destination_instance_offset": 72,
                        "context_offset": 8,
                        "record_count_offset": 6,
                    }
                ]
            },
        },
        indent=2,
    ) + "\n"
    path.write_text(original, encoding="utf-8")
    partial = CalibrationResult(
        specs=(
            MessageSpec(
                "INVENTORY_TRANSFER",
                0x2222,
                255,
                item_id_offset=34,
                quantity_offset=38,
                item_instance_offset=69,
                context_offset=21,
            ),
        ),
        ignored=(),
        frames_scanned=1,
        retention=CalibrationRetention(1, 1, 0, 0, 0, 0),
    )

    with pytest.raises(CalibrationAuthorityError, match="auto calibration is incomplete"):
        update_profile(partial, path, backup=False)

    assert path.read_text(encoding="utf-8") == original


def test_profile_dedupe_includes_context_and_inventory_slot(tmp_path):
    first = MessageSpec(
        "INVENTORY_TRANSFER",
        0x1234,
        50,
        item_id_offset=10,
        quantity_offset=14,
        context_offset=5,
        inventory_slot_offset=9,
    )
    second = MessageSpec(
        "INVENTORY_TRANSFER",
        0x1234,
        50,
        item_id_offset=10,
        quantity_offset=14,
        context_offset=6,
        inventory_slot_offset=8,
    )

    update = update_profile([first, second], tmp_path / "opcodes.json")

    assert len(update.added) == 2


def test_runtime_profile_preserves_distinct_same_opcode_layouts(tmp_path):
    profile_path = tmp_path / "opcodes.json"
    first = MessageSpec(
        "STORAGE_ITEM_DELTA",
        0x126D,
        257,
        item_id_offset=36,
        quantity_added_offset=40,
        context_offset=27,
        destination_instance_offset=71,
        repeat_stride=222,
    )
    second = MessageSpec(
        "STORAGE_ITEM_DELTA",
        0x126D,
        260,
        item_id_offset=36,
        quantity_added_offset=40,
        context_offset=27,
        destination_instance_offset=71,
        repeat_stride=225,
    )

    update_profile([first, second], profile_path, backup=False)
    loaded = event_specs_from_profile(load_opcode_profile(profile_path))

    assert len(loaded.specs) == 2
    assert {
        (
            spec.min_message_length,
            spec.single_record_message_length,
            spec.repeat_stride,
        )
        for spec in loaded.specs
    } == {
        (257, 257, 222),
        (260, 260, 225),
    }


def test_runtime_loot_profile_preserves_disjoint_length_variants(tmp_path):
    profile_path = tmp_path / "opcodes.json"
    payload = {
        "version": 1,
        "profile_active": True,
        "specs": {
            "LOOT_PREVIEW": [
                {
                    "event": "LOOT_PREVIEW",
                    "opcode": "0x1643",
                    "length": 244,
                    "item_id_offset": 23,
                    "quantity_offset": 27,
                    "item_instance_offset": 58,
                },
                {
                    "event": "LOOT_PREVIEW",
                    "opcode": "0x1643",
                    "length": 252,
                    "item_id_offset": 23,
                    "quantity_offset": 27,
                    "item_instance_offset": 66,
                },
            ]
        },
    }
    profile_path.write_text(json.dumps(payload), encoding="utf-8")

    loaded = event_specs_from_profile(load_opcode_profile(profile_path))

    assert len(loaded.specs) == 2
    assert {
        (spec.item_instance_offset, spec.single_record_message_length)
        for spec in loaded.specs
    } == {(58, 244), (66, 252)}

    events = []
    scanner = TargetMessageScanner(
        lambda event, _raw: events.append(event),
        loaded.specs,
    )
    context = PacketContext(
        timestamp=1.0,
        flow=FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000),
    )
    for length, instance_offset, instance in (
        (244, 58, bytes.fromhex("0102030405060708")),
        (252, 66, bytes.fromhex("1112131415161718")),
    ):
        message = bytearray(length)
        message[0:2] = length.to_bytes(2, "little")
        message[3:5] = (0x1643).to_bytes(2, "little")
        message[23:27] = (7003).to_bytes(4, "little")
        message[27:31] = (3).to_bytes(4, "little")
        message[instance_offset : instance_offset + 8] = instance
        scanner.scan_standalone(bytes(message), context)

    assert [
        (event.message_length, event.item_instance) for event in events
    ] == [
        (244, bytes.fromhex("0102030405060708")),
        (252, bytes.fromhex("1112131415161718")),
    ]


def test_runtime_loot_profile_rejects_overlapping_instance_only_variants(
    tmp_path,
):
    profile_path = tmp_path / "opcodes.json"
    payload = {
        "version": 1,
        "profile_active": True,
        "specs": {
            "LOOT_PREVIEW": [
                {
                    "event": "LOOT_PREVIEW",
                    "opcode": "0x1643",
                    "length": 244,
                    "item_id_offset": 23,
                    "quantity_offset": 27,
                    "item_instance_offset": 58,
                },
                {
                    "event": "LOOT_PREVIEW",
                    "opcode": "0x1643",
                    "length": 244,
                    "item_id_offset": 23,
                    "quantity_offset": 27,
                    "item_instance_offset": 66,
                },
            ]
        },
    }
    profile_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(
        ProfileError,
        match=r"Ambiguous LOOT_PREVIEW.*0x1643.*58.*66",
    ):
        event_specs_from_profile(load_opcode_profile(profile_path))


@pytest.mark.parametrize(
    "second_layout",
    (
        {
            "length": None,
            "item_id_offset": 23,
            "quantity_offset": 27,
            "item_instance_offset": 58,
        },
        {
            "length": 244,
            "item_id_offset": 33,
            "quantity_offset": 37,
            "item_instance_offset": 68,
        },
    ),
    ids=("exact-and-open-length", "different-record-offsets"),
)
def test_runtime_loot_profile_rejects_every_overlapping_opcode_layout(
    tmp_path,
    second_layout,
):
    profile_path = tmp_path / "opcodes.json"
    second = {
        "event": "LOOT_PREVIEW",
        "opcode": "0x1643",
        **second_layout,
    }
    payload = {
        "version": 1,
        "profile_active": True,
        "specs": {
            "LOOT_PREVIEW": [
                {
                    "event": "LOOT_PREVIEW",
                    "opcode": "0x1643",
                    "length": 244,
                    "item_id_offset": 23,
                    "quantity_offset": 27,
                    "item_instance_offset": 58,
                },
                second,
            ]
        },
    }
    profile_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(
        ProfileError,
        match=r"Ambiguous LOOT_PREVIEW.*overlapping runtime message-length",
    ):
        event_specs_from_profile(load_opcode_profile(profile_path))


def test_advanced_loot_merge_rejects_ambiguity_before_backup_or_write(tmp_path):
    profile_path = tmp_path / "opcodes.json"
    first = MessageSpec(
        "LOOT_PREVIEW",
        0x1643,
        244,
        item_id_offset=23,
        quantity_offset=27,
        item_instance_offset=58,
    )
    second = MessageSpec(
        "LOOT_PREVIEW",
        0x1643,
        244,
        item_id_offset=23,
        quantity_offset=27,
        item_instance_offset=66,
    )
    update_profile([first], profile_path)
    original = profile_path.read_bytes()

    with pytest.raises(ProfileError, match="replace the LOOT_PREVIEW family"):
        update_profile([second], profile_path, replace=False)

    assert profile_path.read_bytes() == original
    assert not (tmp_path / "opcodes_backups").exists()

    replacement = update_profile([second], profile_path, backup=False)
    loaded = event_specs_from_profile(load_opcode_profile(profile_path))

    assert replacement.written
    assert [spec.item_instance_offset for spec in loaded.specs] == [66]


def test_profile_update_does_not_runtime_validate_incomplete_nonloot_specs(tmp_path):
    profile_path = tmp_path / "opcodes.json"
    incomplete_evidence = MessageSpec(
        "STORAGE_ITEM_DELTA",
        0x126D,
        257,
    )

    update = update_profile([incomplete_evidence], profile_path, backup=False)
    written = json.loads(profile_path.read_text(encoding="utf-8"))

    assert update.written
    assert written["specs"]["STORAGE_ITEM_DELTA"] == [
        incomplete_evidence.to_json_dict()
    ]


def test_profile_records_calibration_item_and_uses_unique_backups(tmp_path):
    path = tmp_path / "opcodes.json"
    path.write_text(
        json.dumps({"version": 1, "profile_active": True, "specs": {}}),
        encoding="utf-8",
    )
    first_result = CalibrationResult(
        (MessageSpec("LOOT_PREVIEW", 1, 50, item_id_offset=5, quantity_offset=9),),
        (),
        1,
        calibration_item_id=99123,
        retention=CalibrationRetention(1, 1, 0, 0, 0, 0),
    )
    first = update_profile(first_result, path)
    second = update_profile(
        [MessageSpec("LOOT_PREVIEW", 2, 50, item_id_offset=5, quantity_offset=9)],
        path,
    )

    assert first.backup_path is not None
    assert second.backup_path is not None
    assert first.backup_path != second.backup_path
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["calibration_item_id"] == 99123
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"version": 1, "profile_active": "false", "specs": {}},
        {"version": "one", "specs": {}},
        {"version": 1, "specs": {"INVENTORY_TRANSFER": {}}},
        {
            "version": 1,
            "specs": {
                "INVENTORY_TRANSFER": [
                    {"event": "LOOT_PREVIEW", "opcode": "0x1234"}
                ]
            }
        },
        {
            "version": 1,
            "specs": {},
            "origin_companion_families": [
                {
                    "detection": "opcode-only",
                    "delta_opcode": "0x0D7E",
                    "companion_opcodes": ["0x0F7E", "0x0DE1"],
                    "companion_lengths": [60, 23],
                    "observations": 2,
                }
            ],
        },
        {
            "version": 1,
            "specs": {
                "STORAGE_ITEM_DELTA": [
                    {
                        "event": "STORAGE_ITEM_DELTA",
                        "opcode": "0x1234",
                        "length": 100,
                        "item_id_offset": 20,
                        "quantity_added_offset": 24,
                        "destination_instance_offset": 55,
                        "context_offset": 18,
                        "record_count_offset": 6,
                    }
                ]
            }
        },
        {
            "version": 1,
            "specs": {
                "STORAGE_ITEM_DELTA": [
                    {
                        "event": "STORAGE_ITEM_DELTA",
                        "opcode": "0x1234",
                        "length": 100,
                        "item_id_offset": 20,
                        "quantity_added_offset": 24,
                        "destination_instance_offset": 55,
                        "context_offset": 8,
                        "record_count_offset": 19,
                    }
                ]
            }
        },
    ],
)
def test_malformed_profiles_raise_public_profile_error(tmp_path, payload):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProfileError):
        load_opcode_profile(path)


@pytest.mark.parametrize(
    "payload",
    [
        {"profile_active": True, "specs": {}},
        {"version": 2, "profile_active": True, "specs": {}},
    ],
    ids=("missing-version", "unsupported-version"),
)
def test_profile_requires_exact_schema_version_one(tmp_path, payload):
    path = tmp_path / "unsupported-version.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProfileError, match=r"version.*must be 1"):
        load_opcode_profile(path)


def test_event_extra_is_deeply_immutable_hashable_and_json_safe():
    original = {"nested": {"values": [1, 2]}, "_vendor": "preserved"}
    event = BDOEvent("test", 0.0, Flow("a", 1, "b", 2), 1, 1, extra=original)
    original["nested"]["values"].append(3)

    with pytest.raises(TypeError):
        event.extra["new"] = True
    with pytest.raises(TypeError):
        event.extra["nested"]["new"] = True
    assert hash(event) == hash(event)
    assert event.to_dict()["extra"] == {
        "nested": {"values": [1, 2]},
        "_vendor": "preserved",
    }
    assert event.to_dict()["timestamp_iso"] == "1970-01-01T00:00:00.000Z"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"item_id": 0},
        {"item_id": -1},
        {"item_id": 1, "quantity": 0},
        {"item_id": 1, "context_frames": 0},
        {"item_id": 1, "min_confidence": float("nan")},
        {"item_id": 1, "min_confidence": 1.1},
    ],
)
def test_calibration_rejects_invalid_options(kwargs):
    with pytest.raises(ValueError):
        calibrate_frames([], **kwargs)


def test_calibrate_live_cleans_up_when_waiting_raises(monkeypatch):
    state = {"entered": False, "exited": False, "stopped": False}

    class FakeSession:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            state["entered"] = True
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            state["exited"] = True

        def raise_if_failed(self):
            return None

        def stop(self):
            state["stopped"] = True
            return CalibrationResult(
                (),
                (),
                0,
                retention=CalibrationRetention(0, 0, 0, 0, 0, 0),
            )

    def fail_sleep(seconds):
        raise RuntimeError("wait failed")

    monkeypatch.setattr(calibration_module, "CalibrationSession", FakeSession)
    monkeypatch.setattr("time.sleep", fail_sleep)

    with pytest.raises(RuntimeError, match="wait failed"):
        calibration_module.calibrate_live(item_id=1, capture_seconds=1)

    assert state == {"entered": True, "exited": True, "stopped": False}


def test_filter_rejects_accidental_string_iterables():
    with pytest.raises(TypeError, match="not a string"):
        EventFilter.from_values(sources="Mob Drop")


def test_event_filter_constructor_normalizes_and_freezes_inputs():
    sources = {"Mob Drop"}
    storage_ids = {0x0020}
    event_filter = EventFilter(sources=sources, storage_ids=storage_ids)
    sources.add("Storage")
    storage_ids.add(0x0058)

    assert event_filter.sources == frozenset({"Mob Drop"})
    assert event_filter.storage_ids == frozenset({0x0020})
