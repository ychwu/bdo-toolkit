"""Synthetic regressions for public API and transport hardening."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bdo_toolkit import BDOEvent, Flow, ProfileError, load_opcode_profile, replay_pcap
from bdo_toolkit import capture as capture_module
from bdo_toolkit._capture_backend import import_scapy
from bdo_toolkit._engine import PacketEngine
from bdo_toolkit._protocol import BDOFrame, CURRENT_EVENT_SPECS, FlowKey, PacketContext
from bdo_toolkit._specs import load_spec_profile
from bdo_toolkit.calibration import (
    CalibrationResult,
    DirectionMismatchError,
    MessageSpec,
    calibrate_frames,
    update_profile,
)
from bdo_toolkit import calibration as calibration_module


def _loot_preview_frame(item_id: int = 7003, quantity: int = 3) -> bytes:
    message = bytearray(31)
    message[0:2] = (31).to_bytes(2, "little")
    message[3:5] = (0x1643).to_bytes(2, "little")
    message[23:27] = item_id.to_bytes(4, "little")
    message[27:31] = quantity.to_bytes(4, "little")
    return bytes(message)


def _engine(events: list) -> PacketEngine:
    return PacketEngine(
        server_ports=(8889,),
        event_specs=CURRENT_EVENT_SPECS,
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
    contradictory: bool = False,
) -> BDOFrame:
    length = 261
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = opcode.to_bytes(2, "little")
    message[8:12] = bytes.fromhex("20000000")
    if contradictory:
        message[20:24] = bytes.fromhex("d0f205a3")
    message[37:41] = item_id.to_bytes(4, "little")
    message[41:45] = quantity.to_bytes(4, "little")
    message[72:80] = b"\x22" * 8
    return BDOFrame(
        index=0,
        message=bytes(message),
        context=PacketContext(
            timestamp=1000.0,
            flow=FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000),
        ),
        stream_sequence=100,
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
    events = replay_pcap("unused.pcapng", ignore_opcode_profile=True)

    assert next(events).item_id == 7003
    assert progress == ["first"]
    events.close()


def test_callback_collector_does_not_retain_delivered_events():
    delivered: list[BDOEvent] = []
    collector = capture_module._EventCollector(
        server_ports=(8889,),
        on_event=delivered.append,
        ignore_opcode_profile=True,
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
        list(replay_pcap(capture))

    capture.unlink()
    assert not capture.exists()


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


def test_post_patch_storage_profile_keeps_context_and_stride(tmp_path):
    frame = _storage_frame(opcode=0x9999)
    result = calibrate_frames(
        [frame],
        item_id=99123,
        quantity=3,
        action="inventory-to-storage",
    )
    delta = next(spec for spec in result.specs if spec.event == "STORAGE_ITEM_DELTA")

    assert delta.context_offset == 8
    assert delta.repeat_stride == 226

    profile_path = tmp_path / "nested" / "opcodes.json"
    update_profile(result, profile_path, action="inventory-to-storage")
    loaded = load_spec_profile(profile_path)
    decode_spec = next(spec for spec in loaded.specs if spec.opcode == 0x9999)
    assert decode_spec.source_context_offset == 8
    assert decode_spec.repeat_stride == 226

    message = bytearray(487)
    message[0:2] = (487).to_bytes(2, "little")
    message[3:5] = (0x9999).to_bytes(2, "little")
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
            ),
        ],
        profile_path,
        backup=False,
    )
    loaded = load_spec_profile(profile_path, missing_ok=False)
    by_label = {spec.label: spec for spec in loaded.specs}

    assert by_label["INVENTORY_TRANSFER"].single_record_message_length == 254
    assert by_label["INVENTORY_TO_STORAGE"].repeat_stride is None
    assert by_label["INVENTORY_TO_STORAGE"].single_record_message_length is None

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


def test_calibration_discovers_changed_context_and_mixed_batch_stride(tmp_path):
    message = bytearray(479)
    message[0:2] = (479).to_bytes(2, "little")
    message[3:5] = (0x0D7E).to_bytes(2, "little")
    message[25:29] = bytes.fromhex("20000000")
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

    result = calibrate_frames(
        [frame],
        item_id=5004,
        quantity=6,
        action="inventory-to-storage",
    )
    delta = next(spec for spec in result.specs if spec.event == "STORAGE_ITEM_DELTA")

    assert delta.length == 258
    assert delta.context_offset == 25
    assert delta.repeat_stride == 221

    profile_path = tmp_path / "opcodes.local"
    update_profile(result, profile_path, backup=False)
    loaded = load_spec_profile(profile_path, missing_ok=False)
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
        [reference, record],
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


def test_empty_profile_update_is_a_true_noop(tmp_path):
    path = tmp_path / "opcodes.json"
    original = '{"sentinel": true}\n'
    path.write_text(original, encoding="utf-8")

    update = update_profile(CalibrationResult((), (), 0), path)

    assert not update.written
    assert update.backup_path is None
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


def test_profile_records_calibration_item_and_uses_unique_backups(tmp_path):
    path = tmp_path / "opcodes.json"
    path.write_text("{}", encoding="utf-8")
    first_result = CalibrationResult(
        (MessageSpec("LOOT_PREVIEW", 1, 50, item_id_offset=5, quantity_offset=9),),
        (),
        1,
        calibration_item_id=99123,
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
        {"profile_active": "false", "specs": {}},
        {"version": "one", "specs": {}},
        {"specs": {"INVENTORY_TRANSFER": {}}},
        {
            "specs": {
                "INVENTORY_TRANSFER": [
                    {"event": "LOOT_PREVIEW", "opcode": "0x1234"}
                ]
            }
        },
        {
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
    ],
)
def test_malformed_profiles_raise_public_profile_error(tmp_path, payload):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProfileError):
        load_opcode_profile(path)


def test_event_extra_is_deeply_immutable_hashable_and_json_safe():
    original = {"nested": {"values": [1, 2]}}
    event = BDOEvent("test", 0.0, Flow("a", 1, "b", 2), 1, 1, extra=original)
    original["nested"]["values"].append(3)

    with pytest.raises(TypeError):
        event.extra["new"] = True
    with pytest.raises(TypeError):
        event.extra["nested"]["new"] = True
    assert hash(event) == hash(event)
    assert event.to_dict()["extra"] == {"nested": {"values": [1, 2]}}
    assert event.to_dict()["timestamp_iso"] == "1970-01-01T00:00:00.000Z"
    assert "timestamp_text" not in event.to_dict()


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


def test_capture_rejects_invalid_queue_before_starting_scapy():
    generator = capture_module.capture_live(event_queue_size=0)
    with pytest.raises(ValueError, match="event_queue_size"):
        next(generator)


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

        def stop(self):
            state["stopped"] = True
            return CalibrationResult((), (), 0)

    def fail_sleep(seconds):
        raise RuntimeError("wait failed")

    monkeypatch.setattr(calibration_module, "CalibrationSession", FakeSession)
    monkeypatch.setattr("time.sleep", fail_sleep)

    with pytest.raises(RuntimeError, match="wait failed"):
        calibration_module.calibrate_live(item_id=1, capture_seconds=1)

    assert state == {"entered": True, "exited": True, "stopped": False}


def test_filter_rejects_accidental_string_iterables():
    from bdo_toolkit import EventFilter

    with pytest.raises(TypeError, match="not a string"):
        EventFilter.from_values(sources="Mob Drop")
