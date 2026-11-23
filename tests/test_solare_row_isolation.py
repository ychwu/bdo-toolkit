import os
from pathlib import Path
from dataclasses import replace
from unittest.mock import patch
import pytest
from bdo_toolkit.solare import replay_solare
from bdo_toolkit.solare._result import build_solare_result
from fixture_paths import optional_fixture_path
from bdo_toolkit.solare._detail_learning import (
    _extract_records,
    _learn_record_layouts,
    _raw_base_candidates,
)


@pytest.fixture(scope="module")
def original():
    path = Path(
        os.environ.get(
            "SOLARE_ISOLATION_FIXTURE",
            optional_fixture_path(
                "solare--leaderboard-complete-kr-post-patch--9731c37014"
            ),
        )
    )
    if not path.is_file():
        pytest.skip("optional Solare capture absent")
    with patch(
        "bdo_toolkit.solare.replay.build_solare_result", wraps=build_solare_result
    ) as build:
        result = replay_solare(path)
    frames, health = build.call_args.args
    discovery = build.call_args.kwargs["_discovery"]
    rich, overall = discovery.rich, discovery.overall

    def records(family):
        return _extract_records(
            family.frames,
            family,
            expected_frames=family.frame_count,
            expected_records=family.record_count,
        )

    left, right = _learn_record_layouts(
        records(rich),
        records(overall),
        learn_rich=True,
        learn_overall=True,
        retain_raw_extensions=False,
    )
    return result, frames, health, ((rich, left), (overall, right))


@pytest.mark.parametrize("field", ["equipment", "performance", "elo", "two"])
@pytest.mark.parametrize("table_index", [0, 1], ids=["class", "overall"])
def test_single_player_fallback(original, field, table_index):
    baseline, frames, health, tables = original
    family, layout = tables[table_index]
    index = 14
    (gear,) = _raw_base_candidates(
        layout.records.rows,
        layout.performance.occupancies,
        value_count=126,
        slot_size=2001,
        minimum_text_length=300,
        maximum_text_length=500,
    )
    offset = {
        "equipment": gear,
        "performance": layout.performance.wins_offset,
        "elo": layout.elo_offset,
        "two": gear,
    }[field]
    observed = list(frames)
    for i in range(index, index + (2 if field == "two" else 1)):
        frame, base = (
            family.short_record_locations[i]
            if family.short_record_locations
            else (family.frames[i // 2], family.record_stride * (i % 2))
        )
        pos = frames.index(frame)
        data = bytearray(observed[pos].message)
        start = base + offset
        damaged = 0xFFFFFFFF
        if field == "performance":
            damaged = int.from_bytes(data[start : start + 4], "little") + 1
        data[start : start + 4] = damaged.to_bytes(4, "little")
        observed[pos] = replace(frame, message=bytes(data))
    result = build_solare_result(observed, health)
    if field == "two":
        assert not result.warnings
        assert result.snapshot is None or "equipment" not in (
            result.snapshot.overall_capabilities
            if table_index
            else result.snapshot.class_table_capabilities
        )
        return
    assert result.complete and len(result.warnings) == 1
    assert family.names[index] in result.warnings[0] and field in result.warnings[0]
    assert result.to_dict()["warnings"] == list(result.warnings)
    target, other = (
        ("overall_top_100", "players")
        if table_index
        else ("players", "overall_top_100")
    )
    assert getattr(result.snapshot, other) == getattr(baseline.snapshot, other)
    expected = list(getattr(baseline.snapshot, target))
    player = expected[index]
    if field == "elo":
        expected[index] = replace(player, elo=None)
    else:
        slot, *others = player.classes_played
        slot = (
            replace(slot, equipment=None)
            if field == "equipment"
            else replace(slot, matches=None, wins=None, draws=None, losses=None)
        )
        expected[index] = replace(player, classes_played=(slot, *others))
    assert tuple(expected) == getattr(result.snapshot, target)
    assert result.snapshot.snapshot_id != baseline.snapshot.snapshot_id
