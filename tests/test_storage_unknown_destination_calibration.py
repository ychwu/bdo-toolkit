"""Regression coverage for dynamic storage-destination calibration."""

from __future__ import annotations

from dataclasses import replace

import pytest

from fixture_paths import fixture_path, has_fixture_pcaps
from bdo_toolkit.calibration import calibrate_frames, collect_frames_pcap


pytestmark = pytest.mark.skipif(
    not has_fixture_pcaps(),
    reason="local pcap fixtures not present (private captures)",
)


def test_known_town_establishes_column_for_same_opcode_unknown_town():
    """An unregistered nonzero town must validate, not veto, the learned field."""

    frames = collect_frames_pcap(
        fixture_path('storage--manual-unstackable-batch--46b846b370')
    ) + collect_frames_pcap(fixture_path('storage--manual-stack-deposit--d765fe48ce'))
    known = next(frame for frame in frames if frame.opcode == 0x0E6A)

    unknown_storage_id = 0x12345678
    unknown_message = bytearray(known.message)
    unknown_message[8:12] = unknown_storage_id.to_bytes(4, "little")
    unknown = replace(
        known,
        index=max(frame.index for frame in frames) + 1,
        message=bytes(unknown_message),
    )

    result = calibrate_frames(
        [*frames, unknown],
        item_id=1000306,
        quantity=1,
        action="inventory-to-storage",
    )

    storage_specs = [
        spec for spec in result.specs if spec.event == "STORAGE_ITEM_DELTA"
    ]
    assert len(storage_specs) == 1
    assert storage_specs[0].opcode == known.opcode
    assert storage_specs[0].context_offset == 8
    assert int.from_bytes(unknown.message[8:12], "little") == unknown_storage_id
