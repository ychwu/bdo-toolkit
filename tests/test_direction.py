"""Transfer-direction classification tests over labeled fixtures.

These lock in the 2026-07-07 re-audit findings: the reference-frame and
context-label features classify direction opcode-free across both observed
opcode generations, batch deposits fall in the storage-delta family, and auto
calibration never silently mislabels a wrong-direction capture.
"""

import pytest

from fixture_paths import fixture_path, has_fixture_pcaps
from bdo_toolkit.calibration import (
    DirectionMismatchError,
    calibrate_pcap,
    collect_frames_pcap,
    detect_transfer_family,
    update_profile,
)
from bdo_toolkit._protocol import MAX_PLAUSIBLE_ITEM_ID

requires_fixtures = pytest.mark.skipif(
    not has_fixture_pcaps(),
    reason="local pcap fixtures not present (private captures)",
)

# (fixture, item_id, expected family) — labeled by the repo owner.
STORAGE_TO_INVENTORY = [  # item entering inventory -> receipt family
    ("1000707_inven_transfer_from_storage.pcapng", 1000707, "into_inventory"),
    ("new_potato.pcapng", 7003, "into_inventory"),
    ("potato_qty6.pcapng", 7003, "into_inventory"),
    ("potato_qty20_storage.pcapng", 7003, "into_inventory"),
    ("hit_1_5_unstackable.pcapng", 1000306, "into_inventory"),
    ("base_ring.pcapng", 12031, "into_inventory"),
    ("DUO_ring.pcapng", 33566463, "into_inventory"),
    ("duo_item_s_to_i.pcapng", 34105233, "into_inventory"),
    ("tet_item_storage_to_inven.pcapng", 318780390, "into_inventory"),
]
INVENTORY_TO_STORAGE = [  # item entering storage -> storage-delta family
    ("new_potato_1_1_1.pcapng", 7003, "into_storage"),
    ("new_potato_3_tostorage.pcapng", 7003, "into_storage"),
    ("potato_leaving_inventory_qty20.pcapng", 7003, "into_storage"),
    ("potato_leaving_inventory_qty10.pcapng", 7003, "into_storage"),
    ("potato_transfer_test_3.pcapng", 7003, "into_storage"),
    ("potato_7_3_to_storage.pcapng", 7003, "into_storage"),
    ("new_item_to_storage_13_42.pcapng", 44195, "into_storage"),
    # Multi-record unstackable deposit: NO reference frame at all — classified
    # by the intrinsic offset-8 storage-delta context, not the windowed
    # reference. This is the case that motivated the intrinsic feature.
    ("1000306_qty5_unstackable_i2s.pcapng", 1000306, "into_storage"),
]
# Worker deposits are structurally storage deltas (item enters storage) and
# must classify as into_storage, not as a separate direction.
WORKER_DEPOSITS = [
    ("5960_qty1_and_4015_qty1_multi.pcapng", 5960, "into_storage"),
    ("5960_qty1_and_4015_qty1_multi.pcapng", 4015, "into_storage"),
    ("worker_4607.pcapng", 4607, "into_storage"),
]


def _classify_primary_record(fixture, item_id):
    """Find the big record frame for item_id and classify its family."""
    frames = collect_frames_pcap(fixture_path(fixture))
    item_bytes = item_id.to_bytes(4, "little")
    for frame in frames:
        at = 0
        message = frame.message
        while True:
            off = message.find(item_bytes, at)
            if off < 0:
                break
            at = off + 1
            if off + 43 > len(message) or frame.length <= 40:
                continue
            qty = int.from_bytes(message[off + 4 : off + 8], "little")
            instance = message[off + 35 : off + 43]
            plausible_instance = instance not in (b"\x00" * 8, b"\xff" * 8)
            if 0 < qty <= 1_000_000 and 0 < item_id <= MAX_PLAUSIBLE_ITEM_ID and plausible_instance:
                family, _, _, _ = detect_transfer_family(frames, frame, off, item_id)
                if family is not None:
                    return family
    return None


@requires_fixtures
@pytest.mark.parametrize(
    "fixture,item_id,expected",
    STORAGE_TO_INVENTORY + INVENTORY_TO_STORAGE + WORKER_DEPOSITS,
    ids=lambda v: v if isinstance(v, str) else str(v),
)
def test_direction_classifier_matches_labels(fixture, item_id, expected):
    assert _classify_primary_record(fixture, item_id) == expected


@requires_fixtures
def test_auto_calibration_on_single_direction_capture_is_clean():
    # A storage->inventory capture must yield ONLY receipt-family specs, never
    # a wrong-direction STORAGE_ITEM_DELTA promoted from the receipt frame.
    result = calibrate_pcap(fixture_path("new_potato.pcapng"), item_id=7003, quantity=10)
    events = {spec.event for spec in result.specs}
    assert "INVENTORY_TRANSFER" in events
    assert "STORAGE_ITEM_DELTA" not in events


@requires_fixtures
def test_auto_calibration_on_inventory_to_storage_capture_is_clean():
    result = calibrate_pcap(
        fixture_path("new_potato_3_tostorage.pcapng"), item_id=7003, quantity=3
    )
    events = {spec.event for spec in result.specs}
    assert "STORAGE_ITEM_DELTA" in events
    assert "INVENTORY_TRANSFER" not in events


@requires_fixtures
def test_auto_calibration_multi_record_deposit_without_reference_frame():
    # Regression: a multi-record unstackable deposit carries NO reference
    # frame, so the windowed feature is absent. Auto must still classify it
    # into_storage via the intrinsic offset-8 context, and the written spec
    # must decode all records. (Bug: auto returned no specs.)
    result = calibrate_pcap(
        fixture_path("1000306_qty5_unstackable_i2s.pcapng"), item_id=1000306, quantity=5
    )
    delta = next(s for s in result.specs if s.event == "STORAGE_ITEM_DELTA")
    assert delta.length == 261 and delta.repeat_stride == 226
    storage_ev = next(e for e in result.evidence if e.detected_family == "into_storage")
    assert storage_ev.storage_context and not storage_ev.reference_frame


@requires_fixtures
def test_explicit_wrong_direction_raises_mismatch():
    # The exact bug the owner hit live: declare inventory-to-storage but the
    # capture is storage-to-inventory. Must refuse, not write garbage.
    with pytest.raises(DirectionMismatchError):
        calibrate_pcap(
            fixture_path("new_potato.pcapng"),
            item_id=7003,
            quantity=10,
            action="inventory-to-storage",
        )


@requires_fixtures
def test_explicit_wrong_direction_raises_mismatch_symmetrically():
    # The mirror case must be just as loud: declared storage-to-inventory on
    # an inventory-to-storage capture refuses instead of returning empty.
    with pytest.raises(DirectionMismatchError):
        calibrate_pcap(
            fixture_path("new_potato_3_tostorage.pcapng"),
            item_id=7003,
            quantity=3,
            action="storage-to-inventory",
        )


def _synthetic_storage_record_frame(item_id, quantity, opcode=0x2222, length=261):
    """A structurally plausible storage-delta record frame, no context label."""
    from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext

    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = opcode.to_bytes(2, "little")
    item_offset = 50
    message[item_offset : item_offset + 4] = item_id.to_bytes(4, "little")
    message[item_offset + 4 : item_offset + 8] = quantity.to_bytes(4, "little")
    message[item_offset + 35 : item_offset + 43] = b"\x11" * 8
    flow = FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000)
    return BDOFrame(
        index=0,
        message=bytes(message),
        context=PacketContext(timestamp=1000.0, flow=flow),
        stream_sequence=1,
    )


def test_explicit_mode_accepts_unclassified_records():
    # If a future patch silences both features, EXPLICIT calibration must
    # remain usable (post-patch recovery path): no contradiction => accept.
    from bdo_toolkit.calibration import calibrate_frames

    frame = _synthetic_storage_record_frame(item_id=99123, quantity=3)
    result = calibrate_frames(
        [frame], item_id=99123, quantity=3, action="inventory-to-storage"
    )
    assert {spec.event for spec in result.specs} == {"STORAGE_ITEM_DELTA"}
    assert result.evidence[0].detected_family is None


def test_auto_mode_drops_unclassified_records():
    # Auto has no declaration to fall back on: unclassifiable => dropped,
    # never guessed. Fail-closed.
    from bdo_toolkit.calibration import calibrate_frames

    frame = _synthetic_storage_record_frame(item_id=99123, quantity=3)
    result = calibrate_frames([frame], item_id=99123, quantity=3)
    assert result.specs == ()
    assert any(e.detected_family is None for e in result.evidence)


def test_reference_frame_does_not_bleed_across_adjacent_transactions():
    # Sequence: [reference, storage_record, second_record_without_label].
    # The reference belongs to the FIRST record; scanning back from the
    # second record must stop at the first record (transaction boundary) and
    # classify the second record as None, never into_storage.
    from bdo_toolkit._protocol import BDOFrame, PacketContext
    from bdo_toolkit.calibration import detect_transfer_family

    record_a = _synthetic_storage_record_frame(item_id=99123, quantity=3)
    record_b = _synthetic_storage_record_frame(item_id=99123, quantity=3, opcode=0x3333)
    ref_message = bytearray(24)
    ref_message[0:2] = (24).to_bytes(2, "little")
    ref_message[3:5] = (0x0C3B).to_bytes(2, "little")
    ref_message[10:14] = (99123).to_bytes(4, "little")
    reference = BDOFrame(
        index=0,
        message=bytes(ref_message),
        context=PacketContext(timestamp=999.9, flow=record_a.context.flow),
        stream_sequence=0,
    )
    frames = [reference, record_a, record_b]

    family_a, _, _, _ = detect_transfer_family(frames, record_a, 50, 99123)
    family_b, ref_b, _, _ = detect_transfer_family(frames, record_b, 50, 99123)
    assert family_a == "into_storage"
    assert family_b is None and not ref_b


def test_intrinsic_storage_context_beats_windowed_reference():
    # A storage-delta context at offset 8 classifies into_storage on its own,
    # with no reference frame present — the intrinsic feature the multi-record
    # deposit relies on.
    from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
    from bdo_toolkit.calibration import detect_transfer_family

    length = 261
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = (0x0E6A).to_bytes(2, "little")
    message[8:12] = bytes.fromhex("20000000")  # batch storage-delta context
    item_offset = 37
    message[item_offset : item_offset + 4] = (99123).to_bytes(4, "little")
    message[item_offset + 4 : item_offset + 8] = (3).to_bytes(4, "little")
    message[item_offset + 35 : item_offset + 43] = b"\x22" * 8
    frame = BDOFrame(
        index=0,
        message=bytes(message),
        context=PacketContext(1000.0, FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000)),
        stream_sequence=1,
    )

    family, ref, ctx, storage_ctx = detect_transfer_family([frame], frame, item_offset, 99123)
    assert family == "into_storage"
    assert storage_ctx and not ref and not ctx


def test_contradictory_intrinsic_features_refuse():
    # If both a high-entropy context label (before record) AND a storage-delta
    # context at offset 8 somehow appear, refuse rather than guess.
    from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
    from bdo_toolkit.calibration import detect_transfer_family

    length = 261
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[8:12] = bytes.fromhex("20000000")  # storage-delta context
    message[20:24] = bytes.fromhex("d0f205a3")  # high-entropy "Storage" label
    item_offset = 37
    message[item_offset : item_offset + 4] = (99123).to_bytes(4, "little")
    message[item_offset + 4 : item_offset + 8] = (3).to_bytes(4, "little")
    message[item_offset + 35 : item_offset + 43] = b"\x22" * 8
    frame = BDOFrame(
        index=0,
        message=bytes(message),
        context=PacketContext(1000.0, FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000)),
        stream_sequence=1,
    )

    family, _, ctx, storage_ctx = detect_transfer_family([frame], frame, item_offset, 99123)
    assert family is None
    assert ctx and storage_ctx


def test_reference_frame_after_record_does_not_count():
    # The reference precedes its record in every labeled capture; a small
    # item-id frame AFTER the record must not classify it.
    from bdo_toolkit._protocol import BDOFrame, PacketContext
    from bdo_toolkit.calibration import detect_transfer_family

    record = _synthetic_storage_record_frame(item_id=99123, quantity=3)
    ref_message = bytearray(24)
    ref_message[0:2] = (24).to_bytes(2, "little")
    ref_message[3:5] = (0x0C3B).to_bytes(2, "little")
    ref_message[10:14] = (99123).to_bytes(4, "little")
    trailing_reference = BDOFrame(
        index=1,
        message=bytes(ref_message),
        context=PacketContext(timestamp=1000.1, flow=record.context.flow),
        stream_sequence=2,
    )

    family, ref, _, _ = detect_transfer_family([record, trailing_reference], record, 50, 99123)
    assert family is None and not ref


def test_multi_record_reference_frame_up_to_mid_gap_length():
    # Reference frames grow ~15 bytes per record (24 single, 39 for a
    # two-record batch deposit). A ~54-byte three-record reference must
    # still classify as into_storage; lengths are bimodal (24-39 vs 251+),
    # so the threshold sits mid-gap rather than at the observed edge.
    from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
    from bdo_toolkit.calibration import detect_transfer_family

    record = _synthetic_storage_record_frame(item_id=99123, quantity=3)
    ref_message = bytearray(54)
    ref_message[0:2] = (54).to_bytes(2, "little")
    ref_message[3:5] = (0x0C3B).to_bytes(2, "little")
    ref_message[10:14] = (99123).to_bytes(4, "little")
    reference = BDOFrame(
        index=0,
        message=bytes(ref_message),
        context=PacketContext(timestamp=999.9, flow=record.context.flow),
        stream_sequence=0,
    )

    family, ref, ctx, _ = detect_transfer_family([reference, record], record, 50, 99123)
    assert family == "into_storage"
    assert ref and not ctx


@requires_fixtures
def test_evidence_records_classification():
    result = calibrate_pcap(fixture_path("new_potato.pcapng"), item_id=7003, quantity=10)
    families = {e.detected_family for e in result.evidence}
    assert "into_inventory" in families
    # The receipt frame carries a context label and no reference frame.
    receipt = next(e for e in result.evidence if e.detected_family == "into_inventory")
    assert receipt.context_label and not receipt.reference_frame


@requires_fixtures
def test_auto_calibration_combined_legs_builds_full_profile(tmp_path):
    """Stitch a storage->inventory and an inventory->storage capture into one
    frame stream (what the guided two-move flow produces) and confirm auto
    calibration recovers both families' opcodes."""
    s2i = collect_frames_pcap(fixture_path("new_potato.pcapng"))
    i2s = collect_frames_pcap(fixture_path("new_potato_3_tostorage.pcapng"))

    from bdo_toolkit.calibration import calibrate_frames

    # Same item id (7003) moved both ways, as in the real guided flow.
    result = calibrate_frames(s2i + i2s, item_id=7003)
    events = {spec.event for spec in result.specs}
    assert {"INVENTORY_TRANSFER", "STORAGE_ITEM_DELTA"} <= events

    profile_path = tmp_path / "opcodes.json"
    update_profile(result, profile_path)  # auto replaces each discovered family
    from bdo_toolkit._specs import load_spec_profile

    profile = load_spec_profile(profile_path)
    assert profile.active
    labels = {spec.label for spec in profile.specs}
    # STORAGE_ITEM_DELTA is emitted as an INVENTORY_TO_STORAGE decode spec.
    assert "INVENTORY_TRANSFER" in labels
    assert "INVENTORY_TO_STORAGE" in labels


def test_special_production_context_is_intrinsic_into_storage():
    # 0x8c050000 is the little-endian Yukjo Street storage destination. It
    # must classify into_storage WITHOUT needing a reference frame, and must
    # never read as a receipt context label.
    from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
    from bdo_toolkit.calibration import detect_transfer_family

    message = bytearray(261)
    message[0:2] = (261).to_bytes(2, "little")
    message[3:5] = (0x0E6A).to_bytes(2, "little")
    message[8:12] = bytes.fromhex("8c050000")
    message[37:41] = (821108).to_bytes(4, "little")
    message[41:45] = (65).to_bytes(4, "little")
    message[72:80] = b"\x22" * 8
    frame = BDOFrame(
        index=0,
        message=bytes(message),
        context=PacketContext(timestamp=1000.0, flow=FlowKey("1.1.1.1", 8889, "2.2.2.2", 50000)),
        stream_sequence=1,
    )
    family, ref, ctx, storage_ctx = detect_transfer_family([frame], frame, 37, 821108)
    assert family == "into_storage"
    assert storage_ctx and not ctx and not ref


def test_arbitrary_town_sized_integer_is_not_a_storage_direction_signal():
    from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
    from bdo_toolkit.calibration import detect_transfer_family

    message = bytearray(100)
    message[0:2] = len(message).to_bytes(2, "little")
    message[10:14] = (0x0034).to_bytes(4, "little")
    item_offset = 50
    message[item_offset : item_offset + 4] = (99123).to_bytes(4, "little")
    frame = BDOFrame(
        index=0,
        message=bytes(message),
        context=PacketContext(
            timestamp=1000.0,
            flow=FlowKey("1.1.1.1", 8889, "2.2.2.2", 50000),
        ),
        stream_sequence=1,
    )

    family, ref, ctx, storage_ctx = detect_transfer_family(
        [frame], frame, item_offset, 99123
    )

    assert family is None
    assert not ref and not ctx and not storage_ctx


def test_current_wrapper_town_key_is_structural_storage_signal():
    from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
    from bdo_toolkit.calibration import detect_transfer_family

    message = bytearray(257)
    message[0:2] = len(message).to_bytes(2, "little")
    message[6] = 1
    message[7:15] = bytes.fromhex("3141592653589793")
    message[16:18] = (1).to_bytes(2, "little")
    item_offset = 36
    message[27:31] = (0x0034).to_bytes(4, "little")
    message[item_offset : item_offset + 4] = (99123).to_bytes(4, "little")
    message[item_offset + 4 : item_offset + 8] = (1).to_bytes(4, "little")
    message[item_offset + 35 : item_offset + 43] = b"\x22" * 8
    frame = BDOFrame(
        index=0,
        message=bytes(message),
        context=PacketContext(
            timestamp=1000.0,
            flow=FlowKey("1.1.1.1", 8889, "2.2.2.2", 50000),
        ),
        stream_sequence=1,
    )

    family, ref, ctx, storage_ctx = detect_transfer_family(
        [frame], frame, item_offset, 99123
    )

    assert family == "into_storage"
    assert storage_ctx and not ref and not ctx
