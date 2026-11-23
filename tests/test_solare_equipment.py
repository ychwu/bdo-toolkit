"""Equipment grammar, class-slot association and semantic identity regressions."""
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from bdo_toolkit.solare import SolareClass, SolareClassPerformance, SolareOverallEntry, SolarePlayer
from bdo_toolkit.solare._detail_learning import (
    _EQUIPMENT_SLOT_CODES, _parse_equipment, decode_equipment_table,
)
from bdo_toolkit.solare.models import solare_snapshot_id


def gear(item=740603):
    values = [v for slot in _EQUIPMENT_SLOT_CODES
              for v in (slot, item, 7, 15252, 15252, 0, 0, 0, 0)]
    return ",".join(map(str, values)).encode().ljust(2001, b"\0")


def test_preserves_slots_crystal_positions_unknowns_and_default_json():
    equipment = _parse_equipment(gear())
    assert equipment is not None and len(equipment) == 14
    assert tuple(e.slot_code for e in equipment) == _EQUIPMENT_SLOT_CODES
    assert all(e.item_id == 740603 and e.crystal_ids == (15252, 15252) for e in equipment)
    assert equipment[0].unknown_fields == (7, 0, 0, 0, 0)
    perf = SolareClassPerformance(0, True, SolareClass(29, "Archer"), equipment=equipment)
    assert len(perf.to_dict()["equipment"]) == 14
    player = SolarePlayer("Example", 1, perf.player_class, classes_played=(perf,))
    changed = replace(player, classes_played=(replace(perf, equipment=_parse_equipment(gear(741317))),))
    assert solare_snapshot_id((player,)) != solare_snapshot_id((changed,))
    assert "equipment" not in replace(perf, equipment=None).to_dict()
    zero = gear().replace(b"15252", b"00000")
    assert _parse_equipment(zero)[0].crystal_ids == (0, 0)


@pytest.mark.parametrize("data", [
    gear()[:-1], b"1" * 2001,
    gear().replace(b"0,740603", b"1,740603", 1),
    gear().replace(b"15252", b"-5252", 1),
    gear().replace(b"15252", b"x5252", 1),
    b"0," + gear()[2:].replace(b",", b";", 1),
])
def test_rejects_malformed_equipment(data):
    assert _parse_equipment(data) is None


def test_table_owns_slots_and_withholds_all_equipment_for_one_bad_slot():
    slots = tuple(SolareClassPerformance(i, i == 0, SolareClass(c, None))
                  for i, c in enumerate((29, 4, 31)))
    player = SolarePlayer("Example", 1, slots[0].player_class, classes_played=slots)
    family = SimpleNamespace(record_count=1, frame_count=1)
    records = SimpleNamespace(rows=(gear(11) + gear(22) + gear(33),), names=(player.name,))
    with patch("bdo_toolkit.solare._detail_learning._extract_records", return_value=records):
        decoded = decode_equipment_table((), family, (player,), gear_offset=0)
        assert [p.equipment[0].item_id for p in decoded[player.name]] == [11, 22, 33]
        records.rows = (gear(11) + bytes(2001) + gear(33),)
        assert decode_equipment_table((), family, (player,), gear_offset=0) is None
    assert all(p.equipment is None for p in player.classes_played)


def test_overall_equipment_divergence_changes_snapshot_identity():
    perf = SolareClassPerformance(0, True, SolareClass(29, "Archer"),
                                  equipment=_parse_equipment(gear()))
    player = SolarePlayer("Example", 1, perf.player_class, classes_played=(perf,))
    overall = SolareOverallEntry("Example", 1, classes_played=(perf,))
    original = solare_snapshot_id((player,), overall_top_100=(overall,))
    assert original == solare_snapshot_id((player,))
    changed = replace(overall, classes_played=(replace(perf, equipment=_parse_equipment(gear(22))),))
    assert solare_snapshot_id((player,), overall_top_100=(changed,)) != original


def test_unknown_boundary_must_be_unique_and_failures_preserve_other_table():
    perf = SolareClassPerformance(0, True, SolareClass(29, "Archer"))
    player = SolarePlayer("Example", 1, perf.player_class, classes_played=(perf,))
    family = SimpleNamespace(record_count=1, frame_count=1)
    records = SimpleNamespace(rows=(gear(),), names=(player.name,))
    with patch("bdo_toolkit.solare._detail_learning._extract_records", return_value=records):
        with patch("bdo_toolkit.solare._detail_learning._raw_base_candidates", return_value=()):
            assert decode_equipment_table((), family, (player,)) is None
        # A separately validated response can still publish equipment.
        assert decode_equipment_table((), family, (player,), gear_offset=0) is not None

def test_one_unavailable_overall_field_changes_identity_until_backfill():
    spec = SolareClass(29, "Archer")
    slot = SolareClassPerformance(0, True, spec, equipment=_parse_equipment(gear()))
    players = tuple(SolarePlayer(name, rank, spec, elo=1400, classes_played=(slot,))
                    for rank, name in enumerate(("First", "Second"), start=1))
    overall = tuple(SolareOverallEntry(p.name, p.global_rank, elo=p.elo,
                    classes_played=p.classes_played) for p in players)
    healthy = solare_snapshot_id(players, overall_top_100=overall)
    assert healthy == solare_snapshot_id(players)
    for partial in (
        replace(overall[0], elo=None),
        replace(overall[0], classes_played=(replace(slot, equipment=None),)),
    ):
        assert solare_snapshot_id(players, overall_top_100=(partial, overall[1])) != healthy
