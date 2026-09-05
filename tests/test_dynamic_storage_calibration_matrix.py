"""Cross-patch storage calibration and replay regression matrix.

The expected offsets below are golden observations about private fixtures, not
inputs to calibration.  Every profile under test is produced from raw frames
without loading or seeding an opcode profile.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from functools import lru_cache

import pytest

from fixture_paths import fixture_path, has_fixture_pcaps
from bdo_toolkit import load_opcode_profile, replay_pcap
from bdo_toolkit._framing import TargetMessageScanner
from bdo_toolkit._specs import event_specs_from_profile
from bdo_toolkit.calibration import (
    CalibrationAuthorityError,
    calibrate_frames,
    collect_frames_pcap,
    update_profile,
)


pytestmark = pytest.mark.skipif(
    not has_fixture_pcaps(),
    reason="local pcap fixtures not present (private captures)",
)


@dataclass(frozen=True)
class _StorageLayoutCase:
    name: str
    opcode: int
    evidence_fixtures: tuple[str, ...]
    item_id: int
    quantity: int
    replay_fixture: str
    base_length: int
    item_offset: int
    context_offset: int
    count_offset: int
    stride: int
    instance_offset: int
    synthesize_legacy_second_count: bool = False


_CASES = (
    _StorageLayoutCase(
        name="july-2-0e6a",
        opcode=0x0E6A,
        evidence_fixtures=(
            'storage--manual-unstackable-batch--46b846b370',
            'storage--manual-stack-deposit--d765fe48ce',
        ),
        item_id=1000306,
        quantity=1,
        replay_fixture='storage--manual-unstackable-batch--46b846b370',
        base_length=261,
        item_offset=37,
        context_offset=8,
        count_offset=6,
        stride=226,
        instance_offset=72,
    ),
    _StorageLayoutCase(
        name="legacy-1b6a",
        opcode=0x1B6A,
        evidence_fixtures=('storage--manual-whole-stack-deposit--6fd7609ce9',),
        item_id=7003,
        # The synthetic two-record witness duplicates the captured quantity-20
        # record. Using the known total makes it outrank the single wrapper as
        # the calibration layout witness without supplying any offsets.
        quantity=40,
        replay_fixture='storage--manual-whole-stack-deposit--6fd7609ce9',
        base_length=264,
        item_offset=43,
        context_offset=35,
        count_offset=19,
        stride=221,
        instance_offset=78,
        synthesize_legacy_second_count=True,
    ),
    _StorageLayoutCase(
        name="july-9-0d7e",
        opcode=0x0D7E,
        evidence_fixtures=(
            'storage--worker-multi-item-deposit--5b8dec558b',
            'storage--worker-deposit-first--44e39f0531',
        ),
        item_id=5004,
        quantity=6,
        replay_fixture='storage--worker-multi-item-deposit--5b8dec558b',
        base_length=258,
        item_offset=37,
        context_offset=25,
        count_offset=35,
        stride=221,
        instance_offset=72,
    ),
    _StorageLayoutCase(
        name="july-17-126d",
        opcode=0x126D,
        evidence_fixtures=(
            'storage--worker-multi-item-post-patch--6b08d80339',
            'inventory--character-switch--148be8bc49',
        ),
        item_id=4802,
        quantity=1,
        replay_fixture='storage--worker-multi-item-post-patch--6b08d80339',
        base_length=257,
        item_offset=36,
        context_offset=27,
        count_offset=16,
        stride=222,
        instance_offset=71,
    ),
    _StorageLayoutCase(
        name="august-7-1c51",
        opcode=0x1C51,
        evidence_fixtures=(
            'inventory--character-switch--4016c4bfa8',
            'storage--manual-deposit-with-worker-traffic--34310f3435',
        ),
        item_id=9580,
        quantity=6,
        replay_fixture='storage--manual-deposit-with-worker-traffic--34310f3435',
        base_length=270,
        item_offset=44,
        context_offset=8,
        count_offset=5,
        stride=228,
        instance_offset=79,
    ),
)


@lru_cache(maxsize=None)
def _fixture_frames(name: str):
    return tuple(collect_frames_pcap(fixture_path(name)))


def _legacy_two_record_witness(case: _StorageLayoutCase, frames):
    """Derive missing count-two evidence from the real legacy wrapper.

    There is no captured multi-record ``0x1B6A`` fixture.  This helper keeps
    the unavoidable historical layout constants in golden test data: it
    duplicates the captured complete record and changes only the declared
    length and count.  Production calibration is still given raw frames only.
    """

    original = next(frame for frame in frames if frame.opcode == case.opcode)
    assert original.length == case.base_length
    assert (
        int.from_bytes(
            original.message[case.count_offset : case.count_offset + 2],
            "little",
        )
        == 1
    )
    assert len(original.message[case.item_offset :]) == case.stride

    message = bytearray(original.message)
    message.extend(original.message[case.item_offset :])
    message[0:2] = len(message).to_bytes(2, "little")
    message[case.count_offset : case.count_offset + 2] = (2).to_bytes(2, "little")
    return replace(
        original,
        index=max(frame.index for frame in frames) + 1,
        message=bytes(message),
    )


def _evidence_for(case: _StorageLayoutCase):
    frames = [
        frame
        for name in case.evidence_fixtures
        for frame in _fixture_frames(name)
    ]
    if case.synthesize_legacy_second_count:
        frames.append(_legacy_two_record_witness(case, frames))
    return frames


def _storage_spec(result):
    specs = [spec for spec in result.specs if spec.event == "STORAGE_ITEM_DELTA"]
    assert len(specs) == 1
    return specs[0]


def test_lone_legacy_1b6a_fixture_has_insufficient_count_authority():
    """Document why the legacy matrix row needs one synthetic witness."""

    with pytest.raises(CalibrationAuthorityError, match="record-count-field"):
        calibrate_frames(
            list(_fixture_frames('storage--manual-whole-stack-deposit--6fd7609ce9')),
            item_id=7003,
            quantity=20,
            action="inventory-to-storage",
        )


@pytest.mark.parametrize("case", _CASES, ids=lambda case: case.name)
def test_storage_layout_is_rediscovered_converted_and_replayed(case, tmp_path):
    frames = _evidence_for(case)
    result = calibrate_frames(
        frames,
        item_id=case.item_id,
        quantity=case.quantity,
        action="inventory-to-storage",
    )
    calibrated = _storage_spec(result)

    assert (
        calibrated.opcode,
        calibrated.length,
        calibrated.item_id_offset,
        calibrated.quantity_added_offset,
        calibrated.context_offset,
        calibrated.record_count_offset,
        calibrated.repeat_stride,
        calibrated.destination_instance_offset,
    ) == (
        case.opcode,
        case.base_length,
        case.item_offset,
        case.item_offset + 4,
        case.context_offset,
        case.count_offset,
        case.stride,
        case.instance_offset,
    )

    profile_path = tmp_path / f"{case.name}.json"
    update_profile(
        result,
        profile_path,
        action="inventory-to-storage",
        backup=False,
    )
    loaded = event_specs_from_profile(load_opcode_profile(profile_path))
    runtime_specs = [
        spec
        for spec in loaded.specs
        if spec.label == "INVENTORY_TO_STORAGE" and spec.opcode == case.opcode
    ]
    assert len(runtime_specs) == 1
    runtime = runtime_specs[0]
    assert (
        runtime.single_record_message_length,
        runtime.item_offset,
        runtime.quantity_offset,
        runtime.source_context_offset,
        runtime.record_count_offset,
        runtime.repeat_stride,
        runtime.storage_instance_offset,
    ) == (
        case.base_length,
        case.item_offset,
        case.item_offset + 4,
        case.context_offset,
        case.count_offset,
        case.stride,
        case.instance_offset,
    )

    # Decode the largest witnessed wrapper through the runtime spec. This
    # checks that count + actual length + calibrated one-record base derive the
    # correct per-message stride; replay does not trust a patch layout table.
    target_frames = [frame for frame in frames if frame.opcode == case.opcode]
    witness = max(target_frames, key=lambda frame: frame.length)
    declared_count = int.from_bytes(
        witness.message[case.count_offset : case.count_offset + 2],
        "little",
    )
    assert declared_count >= 2
    decoded = []
    TargetMessageScanner(
        lambda event, _message: decoded.append(event),
        (runtime,),
    ).scan_standalone(witness.message, witness.context)
    assert len(decoded) == declared_count
    assert [event.record_index for event in decoded] == list(
        range(1, declared_count + 1)
    )
    assert all(event.record_count == declared_count for event in decoded)
    assert [event.record_offset for event in decoded] == [
        case.item_offset + index * case.stride
        for index in range(declared_count)
    ]
    destination = int.from_bytes(
        witness.message[case.context_offset : case.context_offset + 4],
        "little",
    )
    assert destination != 0
    assert all(event.storage_id == destination for event in decoded)

    # Finish at the public PCAP boundary so JSON persistence, profile loading,
    # TCP replay, decoder selection, and event normalization are covered too.
    replayed = [
        event
        for event in replay_pcap(
            fixture_path(case.replay_fixture),
            opcode_profile=profile_path,
        )
        if event.opcode == case.opcode
    ]
    assert replayed
    assert all(event.storage_id is not None for event in replayed)
