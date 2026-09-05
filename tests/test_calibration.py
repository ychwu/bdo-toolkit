"""Calibration discovery, evidence validation, and session configuration."""

from dataclasses import replace
from functools import partial

import pytest

from _support.packets import feed_engine
from fixture_paths import fixture_path, has_fixture_pcaps

from bdo_toolkit import (
    PacketCaptureOptions,
    _capture_backend as capture_backend,
    _capture_runtime as capture_runtime,
    calibration as calibration_module,
    load_opcode_profile,
    replay_pcap,
)
from bdo_toolkit._engine import PacketEngine
from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
from bdo_toolkit._specs import event_specs_from_profile
from bdo_toolkit.calibration import (
    CalibrationAuthorityError,
    CalibrationSession,
    DirectionMismatchError,
    MessageSpec,
    calibrate_frames,
    calibrate_pcap,
    collect_frames_pcap,
    update_profile,
)


requires_fixtures = pytest.mark.skipif(
    not has_fixture_pcaps(),
    reason="local pcap fixtures not present (private captures)",
)


def _specs_by_event(result):
    output = {}
    for spec in result.specs:
        output.setdefault(spec.event, []).append(spec)
    return output


def _calibrate_i2s_with_count_authority(
    fixture_name: str,
    *,
    item_id: int,
    quantity: int,
):
    """Add an independent count shape from the same 0x0E6A generation."""

    frames = collect_frames_pcap(fixture_path(fixture_name))
    authority = collect_frames_pcap(
        fixture_path("1000306_qty5_unstackable_i2s.pcapng")
    )
    return calibrate_frames(
        frames + authority,
        item_id=item_id,
        quantity=quantity,
        action="inventory-to-storage",
    )


@requires_fixtures
def test_calibration_discovers_current_patch_loot_preview():
    result = calibrate_pcap(
        fixture_path("loot_window_potato_3_new.pcapng"),
        item_id=7003,
        quantity=3,
        action="loot-preview",
    )

    specs = _specs_by_event(result)["LOOT_PREVIEW"]
    assert len(specs) == 1
    spec = specs[0]
    assert (spec.opcode, spec.length) == (0x1643, 244)
    assert (spec.item_id_offset, spec.quantity_offset) == (23, 27)
    assert spec.item_instance_offset == 58


@requires_fixtures
def test_calibration_discovers_current_storage_to_inventory():
    result = calibrate_pcap(
        fixture_path("new_potato.pcapng"),
        item_id=7003,
        quantity=10,
        action="storage-to-inventory",
    )

    specs = _specs_by_event(result)
    transfer = specs["INVENTORY_TRANSFER"][0]
    assert (transfer.opcode, transfer.length) == (0x0F16, 255)
    assert (transfer.item_id_offset, transfer.quantity_offset) == (33, 37)
    assert transfer.item_instance_offset == 68
    assert transfer.context_offset == 23

    decrement = specs["SOURCE_CONTAINER_DECREMENT"][0]
    assert (decrement.opcode, decrement.length) == (0x13A5, 40)
    assert decrement.context_offset == 7
    assert decrement.source_instance_offset == 23
    assert decrement.quantity_removed_offset == 32


@requires_fixtures
def test_calibration_storage_to_inventory_with_changed_source_instance():
    result = calibrate_pcap(
        fixture_path("potato_qty6.pcapng"),
        item_id=7003,
        quantity=6,
        action="storage-to-inventory",
    )

    specs = _specs_by_event(result)
    transfer = specs["INVENTORY_TRANSFER"][0]
    assert (transfer.opcode, transfer.length) == (0x0F16, 255)
    decrement = specs["SOURCE_CONTAINER_DECREMENT"][0]
    assert (decrement.opcode, decrement.length) == (0x13A5, 40)
    assert decrement.context_offset == 7
    assert decrement.quantity_removed_offset == 32
    # This capture's source instance differs from the receipt instance. The
    # legacy instance + separator + quantity shape still proves its offset.
    assert decrement.source_instance_offset == 23


@requires_fixtures
def test_profile_from_unstackable_calibration_decodes_single_transfers(tmp_path):
    """End-to-end guard for the multi-record length-poisoning bug."""
    result = calibrate_pcap(
        fixture_path("hit_1_5_unstackable.pcapng"),
        item_id=1000306,
        quantity=5,
        action="storage-to-inventory",
    )
    transfer = _specs_by_event(result)["INVENTORY_TRANSFER"][0]
    # The profile stores the single-record geometry, even though calibration
    # observed a five-record frame, so ordinary one-record transfers remain
    # decodable.
    assert (transfer.opcode, transfer.length) == (0x0F16, 255)
    assert transfer.repeat_stride == 228
    assert transfer.item_id_offset == 33
    assert transfer.quantity_offset == 37

    profile_path = tmp_path / "opcodes.json"
    update_profile(result, profile_path, action="storage-to-inventory", backup=False)

    multi = list(
        replay_pcap(fixture_path("hit_1_5_unstackable.pcapng"), opcode_profile=profile_path)
    )
    single = list(replay_pcap(fixture_path("new_potato.pcapng"), opcode_profile=profile_path))
    assert len(multi) == 5
    assert [(e.item_id, e.quantity) for e in single] == [(7003, 10)]


@requires_fixtures
def test_calibration_discovers_current_inventory_to_storage(tmp_path):
    result = _calibrate_i2s_with_count_authority(
        "new_potato_3_tostorage.pcapng",
        item_id=7003,
        quantity=3,
    )

    specs = _specs_by_event(result)
    stack = specs["SOURCE_STACK_DECREMENT"][0]
    assert (stack.opcode, stack.length) == (0x1A32, 52)
    assert stack.source_instance_offset == 34
    assert stack.quantity_removed_offset == 42

    reference = specs["SOURCE_ITEM_REFERENCE"][0]
    assert (reference.opcode, reference.length) == (0x0C3B, 24)
    assert reference.item_id_offset == 10

    delta = specs["STORAGE_ITEM_DELTA"][0]
    assert (delta.opcode, delta.length) == (0x0E6A, 261)
    assert (delta.item_id_offset, delta.quantity_added_offset) == (37, 41)
    assert delta.destination_instance_offset == 72

    profile_path = tmp_path / "opcodes.json"
    update_profile(result, profile_path, action="inventory-to-storage")
    events = list(
        replay_pcap(
            fixture_path("new_potato_3_tostorage.pcapng"),
            opcode_profile=profile_path,
        )
    )
    assert [(event.event_type, event.item_id, event.quantity) for event in events] == [
        ("storage_delta", 7003, 3)
    ]


@requires_fixtures
@pytest.mark.parametrize(
    (
        "fixture_name",
        "item_id",
        "quantity",
        "expected_opcode",
        "expected_length",
        "expected_instance_offset",
        "expected_quantity_offset",
    ),
    [
        ("new_potato_1_1_1.pcapng", 7003, 1, 0x1A32, 52, 34, 42),
    ],
)
def test_calibration_preserves_stack_layout_when_instances_differ(
    fixture_name,
    item_id,
    quantity,
    expected_opcode,
    expected_length,
    expected_instance_offset,
    expected_quantity_offset,
):
    result = _calibrate_i2s_with_count_authority(
        fixture_name,
        item_id=item_id,
        quantity=quantity,
    )

    stack = _specs_by_event(result)["SOURCE_STACK_DECREMENT"][0]
    assert (stack.opcode, stack.length) == (expected_opcode, expected_length)
    assert stack.source_instance_offset == expected_instance_offset
    assert stack.quantity_removed_offset == expected_quantity_offset


@requires_fixtures
@pytest.mark.parametrize(
    ("fixture_name", "item_id", "quantity"),
    [
        ("new_item_to_storage_13_42.pcapng", 44195, 42),
    ],
)
def test_legacy_single_shape_captures_refuse_partial_storage_authority(
    fixture_name,
    item_id,
    quantity,
):
    with pytest.raises(CalibrationAuthorityError, match="record-count-field"):
        calibrate_pcap(
            fixture_path(fixture_name),
            item_id=item_id,
            quantity=quantity,
            action="inventory-to-storage",
        )


@requires_fixtures
@pytest.mark.parametrize(
    "fixture_name",
    ["calibration_5_inven_0_storage.pcapng"],
)
def test_calibration_discovers_all_current_patch_transfer_specs(fixture_name):
    result = calibrate_pcap(
        fixture_path(fixture_name),
        item_id=7003,
        quantity=5,
    )

    specs = _specs_by_event(result)
    assert set(specs) == {
        "INVENTORY_TRANSFER",
        "SOURCE_CONTAINER_DECREMENT",
        "SOURCE_STACK_DECREMENT",
        "SOURCE_ITEM_REFERENCE",
        "STORAGE_ITEM_DELTA",
    }

    transfer = specs["INVENTORY_TRANSFER"][0]
    assert (transfer.opcode, transfer.length) == (0x194A, 254)
    assert (transfer.item_id_offset, transfer.quantity_offset) == (31, 35)
    assert transfer.item_instance_offset == 66
    assert transfer.context_offset == 27

    container = specs["SOURCE_CONTAINER_DECREMENT"][0]
    assert (container.opcode, container.length) == (0x17E8, 42)
    assert container.context_offset == 13
    assert container.source_instance_offset == 5
    assert container.quantity_removed_offset == 17

    stack = specs["SOURCE_STACK_DECREMENT"][0]
    assert (stack.opcode, stack.length) == (0x11AD, 47)
    assert stack.source_instance_offset == 35
    assert stack.quantity_removed_offset == 27

    reference = specs["SOURCE_ITEM_REFERENCE"][0]
    assert (reference.opcode, reference.length) == (0x0F63, 23)
    assert reference.item_id_offset == 9

    delta = specs["STORAGE_ITEM_DELTA"][0]
    assert (delta.opcode, delta.length) == (0x126D, 257)
    assert (delta.item_id_offset, delta.quantity_added_offset) == (36, 40)
    assert delta.destination_instance_offset == 71


@requires_fixtures
def test_auto_calibration_refuses_a_single_storage_count_shape():
    with pytest.raises(CalibrationAuthorityError, match="record-count-field"):
        calibrate_pcap(
            fixture_path("calibration_to_different_inventory_through_remote.pcapng"),
            item_id=7003,
            quantity=5,
        )


def test_stack_companion_fallback_rejects_incidental_pre_quantity_bytes():
    from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
    from bdo_toolkit._calibration._records import _CalibratedItemRecord
    from bdo_toolkit._calibration._records import _Options
    from bdo_toolkit._calibration.companions import _discover_source_stack_decrement

    flow = FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000)

    frame = partial(_companion_frame, flow=flow)

    quantity = 5
    item_id = 7003
    target_instance = bytes.fromhex("1122334455667788")

    decrement_message = bytearray(47)
    decrement_message[19:27] = bytes.fromhex("00000000be5b0500")
    decrement_message[27:31] = quantity.to_bytes(4, "little")
    # A current-layout source instance follows the quantity and zero gap. It
    # differs from the destination instance, while unrelated nonzero bytes at
    # q-8 reproduce the false offset 19 seen in the remote capture.
    decrement_message[35:43] = bytes.fromhex("0102030405060708")
    decrement_message[43:47] = bytes.fromhex("002bff00")
    decrement = frame(0, 0xBEEF, decrement_message)

    reference_message = bytearray(23)
    reference_message[9:13] = item_id.to_bytes(4, "little")
    reference = frame(1, 0xCAFE, reference_message)

    delta_message = bytearray(257)
    delta_message[36:40] = item_id.to_bytes(4, "little")
    delta_message[40:44] = quantity.to_bytes(4, "little")
    delta_message[71:79] = target_instance
    delta = frame(2, 0xFACE, delta_message)
    record = _CalibratedItemRecord(
        frame=delta,
        item_offset=36,
        item_id=item_id,
        quantity=quantity,
        instance_offset=71,
        instance=target_instance,
        confidence=0.95,
        reasons=(),
    )
    options = _Options(item_id, quantity, "auto", 5, 0.80)

    spec = _discover_source_stack_decrement(
        [decrement, reference, delta], record, options
    )

    assert spec is not None
    assert (spec.opcode, spec.length, spec.quantity_removed_offset) == (
        0xBEEF,
        47,
        27,
    )
    assert spec.source_instance_offset == 35


def test_multi_stack_decrement_calibration_normalizes_base_and_stride():
    from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
    from bdo_toolkit._calibration._records import _CalibratedItemRecord
    from bdo_toolkit._calibration._records import _Options
    from bdo_toolkit._calibration.companions import _discover_source_stack_decrement

    flow = FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000)

    frame = partial(_companion_frame, flow=flow)

    quantity = 1
    item_id = 1000306
    instances = tuple(
        value.to_bytes(8, "little")
        for value in (
            0x008E1BCCCF2C6186,
            0x008E1BCCCF2C6199,
            0x008E1BCCCF2C61AE,
            0x008E1BCCCF2C61CC,
            0x008E1BCCCF2C61E6,
        )
    )
    decrement_message = bytearray(144)
    for index, instance in enumerate(instances):
        delta = index * 23
        decrement_message[34 + delta : 42 + delta] = instance
        decrement_message[42 + delta : 46 + delta] = quantity.to_bytes(
            4, "little"
        )
    decrement = frame(0, 0x1A32, decrement_message)

    delta_message = bytearray(1165)
    delta_message[37:41] = item_id.to_bytes(4, "little")
    delta_message[41:45] = quantity.to_bytes(4, "little")
    delta_message[72:80] = instances[0]
    delta = frame(1, 0x0E6A, delta_message)
    record = _CalibratedItemRecord(
        frame=delta,
        item_offset=37,
        item_id=item_id,
        quantity=quantity,
        instance_offset=72,
        instance=instances[0],
        confidence=0.95,
        reasons=(),
    )

    spec = _discover_source_stack_decrement(
        [decrement, delta],
        record,
        _Options(item_id, quantity, "auto", 5, 0.80),
    )

    assert spec is not None
    assert (spec.opcode, spec.length, spec.repeat_stride) == (0x1A32, 52, 23)
    assert spec.source_instance_offset == 34
    assert spec.quantity_removed_offset == 42


def test_current_decrement_phase_does_not_learn_every_other_record():
    """A cross-record ±8 coincidence must not double the true stride."""

    from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
    from bdo_toolkit._calibration._records import _CalibratedItemRecord
    from bdo_toolkit._calibration._records import _Options
    from bdo_toolkit._calibration.companions import _discover_source_stack_decrement

    flow = FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000)

    frame = partial(_companion_frame, flow=flow)

    quantity = 1
    item_id = 15156
    instances = tuple(
        value.to_bytes(8, "little")
        for value in (
            0x008E1BCCCF2C7101,
            0x008E1BCCCF2C7122,
            0x008E1BCCCF2C7143,
            0x008E1BCCCF2C7164,
        )
    )

    # Current source-decrement records begin at byte 26 and occupy 21 bytes:
    # quantity@26 and instance@39. Consequently record one's instance@39 is
    # also eight bytes before record two's quantity@47. The old normalizer
    # mistook that cross-record coincidence for a field relationship and
    # returned base=68/stride=42/quantity@47.
    decrement_message = bytearray(47 + 3 * 21)
    for index, instance in enumerate(instances):
        delta = index * 21
        decrement_message[26 + delta : 30 + delta] = quantity.to_bytes(
            4, "little"
        )
        decrement_message[39 + delta : 47 + delta] = instance
    decrement = frame(0, 0x1505, decrement_message)

    delta_message = bytearray(270)
    delta_message[44:48] = item_id.to_bytes(4, "little")
    delta_message[48:52] = quantity.to_bytes(4, "little")
    delta_message[79:87] = instances[0]
    delta = frame(1, 0x1C51, delta_message)
    record = _CalibratedItemRecord(
        frame=delta,
        item_offset=44,
        item_id=item_id,
        quantity=quantity,
        instance_offset=79,
        instance=instances[0],
        confidence=0.95,
        reasons=(),
    )

    spec = _discover_source_stack_decrement(
        [decrement, delta],
        record,
        _Options(item_id, quantity, "auto", 5, 0.80),
    )

    assert spec is not None
    assert (spec.opcode, spec.length, spec.repeat_stride) == (0x1505, 47, 21)
    assert spec.source_instance_offset == 39
    assert spec.quantity_removed_offset == 26


def test_decrement_repeat_shape_rejects_incomplete_storage_cardinality():
    from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
    from bdo_toolkit._calibration.companions import _source_stack_repeated_shape

    flow = FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000)
    message = bytearray(110)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x1505).to_bytes(2, "little")
    message[47:51] = (1).to_bytes(4, "little")
    message[89:93] = (1).to_bytes(4, "little")
    message[39:47] = bytes.fromhex("01712ccfcb1b8e00")
    message[81:89] = bytes.fromhex("43712ccfcb1b8e00")
    frame = BDOFrame(
        index=0,
        message=bytes(message),
        context=PacketContext(1000.0, flow),
        stream_sequence=0,
    )

    assert (
        _source_stack_repeated_shape(
            frame,
            (1).to_bytes(4, "little"),
            39,
            expected_record_count=4,
        )
        is None
    )


@requires_fixtures
def test_unstackable_calibration_with_count_authority_discovers_decrement_geometry(
    tmp_path,
):
    from bdo_toolkit import replay_pcap

    capture = fixture_path("1000306_qty5_unstackable_i2s.pcapng")
    frames = collect_frames_pcap(capture) + collect_frames_pcap(
        fixture_path("new_potato_3_tostorage.pcapng")
    )
    result = calibrate_frames(
        frames,
        item_id=1000306,
        quantity=1,
        action="inventory-to-storage",
    )

    stack = _specs_by_event(result)["SOURCE_STACK_DECREMENT"][0]
    assert (stack.opcode, stack.length, stack.repeat_stride) == (0x1A32, 52, 23)
    assert stack.source_instance_offset == 34
    assert stack.quantity_removed_offset == 42

    profile_path = tmp_path / "opcodes.json"
    update_profile(
        result,
        profile_path,
        action="inventory-to-storage",
        backup=False,
    )
    events = list(replay_pcap(capture, opcode_profile=profile_path))
    assert len(events) == 5
    assert all(event.source == "Player Inventory" for event in events)
    assert [
        event.extra["deposit_origin_evidence"]["manual_decrement"][
            "record_index"
        ]
        for event in events
    ] == [1, 2, 3, 4, 5]


@requires_fixtures
def test_one_session_1_4_deposits_and_5_withdrawal_keep_all_strides():
    """The guided single-target workflow retains every repeated geometry."""

    deposit_frames = collect_frames_pcap(
        fixture_path("1000306_qty5_unstackable_i2s.pcapng")
    )
    decrement = deposit_frames[0]
    storage = deposit_frames[1]
    frames = []
    stream_sequence = decrement.stream_sequence or 0

    for count in (1, 4):
        decrement_length = 52 + (count - 1) * 23
        decrement_message = bytearray(decrement.message[:decrement_length])
        decrement_message[0:2] = decrement_length.to_bytes(2, "little")
        frames.append(
            replace(
                decrement,
                index=len(frames),
                message=bytes(decrement_message),
                stream_sequence=stream_sequence,
            )
        )
        stream_sequence += decrement_length

        storage_length = 261 + (count - 1) * 226
        storage_message = bytearray(storage.message[:storage_length])
        storage_message[0:2] = storage_length.to_bytes(2, "little")
        storage_message[6:8] = count.to_bytes(2, "little")
        frames.append(
            replace(
                storage,
                index=len(frames),
                message=bytes(storage_message),
                stream_sequence=stream_sequence,
            )
        )
        stream_sequence += storage_length

    frames.extend(
        collect_frames_pcap(fixture_path("hit_1_5_unstackable.pcapng"))
    )
    result = calibrate_frames(
        frames,
        item_id=1000306,
        quantity=1,
        action="auto",
    )
    specs = _specs_by_event(result)

    assert {
        "INVENTORY_TRANSFER",
        "SOURCE_STACK_DECREMENT",
        "STORAGE_ITEM_DELTA",
    } <= result.events_found
    assert specs["INVENTORY_TRANSFER"][0].repeat_stride == 228
    assert specs["SOURCE_STACK_DECREMENT"][0].repeat_stride == 23
    assert specs["STORAGE_ITEM_DELTA"][0].repeat_stride == 226
    assert specs["STORAGE_ITEM_DELTA"][0].record_count_offset == 6


@pytest.mark.parametrize(
    ("layout", "expected_offsets"),
    [
        ("instance-context-quantity", (13, 5, 17)),
        ("context-instance-quantity-different-instance", (7, 23, 32)),
        ("quantity-instance-context", (34, 21, 5)),
        ("trailing-context-without-exact-instance", None),
        ("ambiguous-trailing-context", None),
    ],
)
def test_container_companion_handles_known_field_orders_safely(
    layout,
    expected_offsets,
):
    from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
    from bdo_toolkit._calibration._records import _CalibratedItemRecord
    from bdo_toolkit._calibration._records import _Options
    from bdo_toolkit._calibration.companions import _discover_source_container_decrement

    flow = FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000)

    frame = partial(_companion_frame, flow=flow)

    quantity = 5
    item_id = 7003
    receipt_instance = bytes.fromhex("1122334455667788")
    source_context = bytes.fromhex("d0f205a3")

    if layout == "instance-context-quantity":
        companion_message = bytearray(42)
        companion_message[5:13] = receipt_instance
        companion_message[13:17] = source_context
        companion_message[17:21] = quantity.to_bytes(4, "little")
    elif layout == "context-instance-quantity-different-instance":
        companion_message = bytearray(40)
        companion_message[7:11] = source_context
        companion_message[23:31] = bytes.fromhex("0102030405060708")
        companion_message[31] = 0x02
        companion_message[32:36] = quantity.to_bytes(4, "little")
    else:
        companion_message = bytearray(
            48 if layout == "ambiguous-trailing-context" else 40
        )
        companion_message[5:9] = quantity.to_bytes(4, "little")
        companion_message[21:29] = (
            bytes.fromhex("0102030405060708")
            if layout == "trailing-context-without-exact-instance"
            else receipt_instance
        )
        companion_message[34:38] = source_context
        if layout == "ambiguous-trailing-context":
            companion_message[40:44] = bytes.fromhex("0471ee0e")
    companion = frame(0, 0xBEEF, companion_message)

    receipt_frame = frame(1, 0xCAFE, bytearray(80))
    receipt = _CalibratedItemRecord(
        frame=receipt_frame,
        item_offset=31,
        item_id=item_id,
        quantity=quantity,
        instance_offset=66,
        instance=receipt_instance,
        confidence=0.95,
        reasons=(),
    )
    options = _Options(item_id, quantity, "auto", 5, 0.80)

    spec = _discover_source_container_decrement(
        [companion, receipt_frame], receipt, options
    )

    if expected_offsets is None:
        assert spec is None
        return

    expected_context, expected_instance, expected_quantity = expected_offsets
    assert spec is not None
    assert (spec.opcode, spec.length) == (0xBEEF, len(companion_message))
    assert spec.context_offset == expected_context
    assert spec.source_instance_offset == expected_instance
    assert spec.quantity_removed_offset == expected_quantity


def test_calibration_session_guards_lifecycle():
    session = CalibrationSession(item_id=7003)
    assert not session.running
    assert session.frames_collected == 0

    # stop() before start() is a usage error, not a silent empty result

    with pytest.raises(RuntimeError, match="not started"):
        session.stop()


def test_calibration_session_uses_shared_packet_capture_options(monkeypatch):
    class FakeSniffer:
        instances = []

        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.running = False
            self.__class__.instances.append(self)

        def start(self):
            self.running = True
            self.kwargs["started_callback"]()

        def stop(self):
            self.running = False

    monkeypatch.setattr(
        capture_runtime,
        "import_scapy",
        lambda: (object(), object(), None, None, None),
    )
    monkeypatch.setattr(capture_runtime, "_is_windows", lambda: False)
    monkeypatch.setattr(capture_runtime, "_new_async_sniffer", FakeSniffer)

    session = CalibrationSession(
        item_id=7003,
        capture_options=PacketCaptureOptions(
            interface="test-interface",
            ports=(9000,),
            use_bpf=False,
            auto_local_ip=False,
        ),
    )
    session.start()

    sniffer = FakeSniffer.instances[-1]
    assert sniffer.kwargs["iface"] == "test-interface"
    assert sniffer.kwargs["filter"] is None
    assert callable(sniffer.kwargs["lfilter"])
    session.stop()


def test_calibration_session_rejects_wrong_capture_options_type():
    with pytest.raises(TypeError, match="PacketCaptureOptions"):
        CalibrationSession(item_id=7003, capture_options=object())


def test_calibration_session_can_disable_automatic_local_ip(monkeypatch):
    class FakeSniffer:
        instances = []

        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.running = False
            self.__class__.instances.append(self)

        def start(self):
            self.running = True
            self.kwargs["started_callback"]()

        def stop(self):
            self.running = False

    monkeypatch.setattr(
        capture_runtime,
        "import_scapy",
        lambda: (object(), object(), None, None, None),
    )
    monkeypatch.setattr(
        capture_runtime,
        "detect_default_capture_target",
        lambda: capture_backend.CaptureTarget(
            interface="default-interface",
            local_ip="192.0.2.25",
            gateway="192.0.2.1",
        ),
    )
    monkeypatch.setattr(capture_runtime, "_is_windows", lambda: False)
    monkeypatch.setattr(capture_runtime, "_new_async_sniffer", FakeSniffer)

    session = CalibrationSession(
        item_id=7003,
        capture_options=PacketCaptureOptions(auto_local_ip=False),
    )
    session.start()

    sniffer = FakeSniffer.instances[-1]
    assert sniffer.kwargs["iface"] == "default-interface"
    assert "dst host" not in sniffer.kwargs["filter"]
    session.stop()


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
    feed_engine(engine, 1, bytes(message))
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
    inventory[45:53] = b"\xff" * 8
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
    feed_engine(engine, 1, bytes(inventory) + bytes(storage))
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
    feed_engine(engine, 1, bytes(message))
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


def _companion_frame(index, opcode, message, *, flow):
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = opcode.to_bytes(2, "little")
    return BDOFrame(
        index=index,
        message=bytes(message),
        context=PacketContext(1000.0 + index, flow),
        stream_sequence=index,
    )
