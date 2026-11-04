"""Safety and ownership contracts for the optional finite character roster."""

from dataclasses import replace

import pytest

from bdo_toolkit._item_state import characters as wire
from bdo_toolkit._item_state.assembly import _CharacterStateAccumulator
from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
from bdo_toolkit.item_state import ItemStateCaptureLimits, ItemStateCaptureLimitError
from test_character_state import _inventory_snapshot_spec, _state_inventory_anchor

ACTIVE = bytes.fromhex("0102030405060708")
ALT = bytes.fromhex("1112131415161718")
FLOW = FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000)


def frame(opcode, data, when=2.0, generation=0):
    data = bytearray(data)
    data[:2] = len(data).to_bytes(2, "little")
    data[3:5] = opcode.to_bytes(2, "little")
    seq = round(when * 10000)
    return BDOFrame(
        index=seq,
        message=bytes(data),
        stream_sequence=seq,
        context=PacketContext(
            timestamp=when, flow=FLOW, stream_start=seq, flow_generation=generation
        ),
    )


def counted(opcode, rows, when=2.0, generation=0):
    header, stride, offset = wire._LAYOUT[opcode]
    data = bytearray(header)
    data[offset : offset + 2] = len(rows).to_bytes(2, "little")
    for row in rows:
        assert len(row) == stride
        data.extend(row)
    return frame(opcode, data, when, generation)


def acc(**kwargs):
    spec = replace(
        _inventory_snapshot_spec(), opcode=0x14BE, repeat_stride=224, item_offset=29
    )
    obj = _CharacterStateAccumulator(
        profile_source="test", specs=(spec,), include_characters=True, **kwargs
    )
    obj.observe_event(replace(_state_inventory_anchor(), opcode=0x14BE))
    return obj


def remote(slot, owner=ALT, code=1, item=735258, sockets=(0, 0)):
    row = bytearray(73)
    row[4] = 1
    row[42] = slot
    row[60:64] = item.to_bytes(4, "little")
    row[64:72] = owner
    row[72] = code
    for off, value in zip((26, 30), sockets):
        row[off : off + 4] = value.to_bytes(4, "little")
    return row


def roster():
    return counted(wire.ROSTER, [bytes(2) + ACTIVE, bytes(2) + ALT])


def identity(obj):
    text = "TestName".encode("utf-16le")
    row = bytearray(269)
    row[21:29] = ACTIVE
    row[113 : 113 + len(text)] = text
    obj.observe_frame(counted(wire.NAMED, [row]))
    row = bytearray(8073)
    row[2983:2991] = ACTIVE
    row[7007 : 7007 + len(text)] = text
    obj.observe_frame(frame(wire.PORTRAIT, row, when=0.99))


def remote_run(obj, *pages, omit=()):
    # Keep original byte positions when a page is omitted from the capture.
    cursor = 40_000
    packets = [frame(73, bytes(5)), *pages, frame(74, bytes(5))]
    for index, packet in enumerate(packets):
        if index not in omit:
            obj.observe_frame(replace(packet, stream_sequence=cursor))
        cursor += len(packet.message)


def test_character_slots_and_lightstones_stay_with_their_owner():
    obj = acc()
    obj.observe_frame(roster())
    identity(obj)
    remote_run(
        obj,
        counted(
            wire.REMOTE,
            [
                remote(32, sockets=(101, 102)),
                remote(33, sockets=(0, 104)),
                remote(32, code=17, item=42),
                remote(32, code=0, item=43),
                remote(32, code=250, item=44),
            ],
        )
    )
    # Raw slot 43 means different things in the two active tables.
    equipped = bytearray(13 + 221 * 46)
    pos = 13 + 221 * 43
    equipped[pos : pos + 4] = (16161).to_bytes(4, "little")
    equipped[pos + 4] = 1
    obj.observe_frame(frame(wire.ACTIVE, equipped))
    row = bytearray(223)
    row[0:4] = (14028).to_bytes(4, "little")
    row[4] = 1
    row[221] = 43
    obj.observe_frame(counted(wire.LIFE_GEAR, [row]))
    snap = obj.snapshot()
    assert snap.schema_version == 6
    active = snap.characters.by_id(ACTIVE.hex())
    alt = snap.characters.by_id(ALT.hex())
    assert active.is_active and active.name == "TestName"
    assert active.other_inventory.observed
    assert active.life_skills.by_role("clothes", activity="farming")[0].raw_slot == 43
    assert active.life_skills.for_activity("hunting")[0].role == "matchlock"
    assert active.life_skills.status == "available"
    assert alt.gear.by_role("artifact_1")[0].lightstones == (101, 102)
    assert alt.gear.by_role("artifact_2")[0].lightstones == (None, 104)
    assert alt.pearl_inventory.items[0].raw_item_id == 42
    assert alt.main_inventory.items[0].raw_item_id == 43
    assert alt.other_inventory.items[0].raw_container == 250
    assert not alt.life_skills.observed
    assert not alt.is_active and alt.name is None and alt.character_class is None
    assert snap.to_dict()["characters"]["by_id"][ALT.hex()]["level"] is None


@pytest.mark.parametrize("bad", ["foreign_owner", "duplicate_slot", "truncated"])
def test_bad_remote_chunk_withholds_the_cohort(bad):
    obj = acc()
    obj.observe_frame(roster())
    first = counted(wire.REMOTE, [remote(32)])
    other = counted(
        wire.REMOTE,
        [remote(32, owner=bytes(8) if bad == "foreign_owner" else ALT)],
        when=2.1,
    )
    if bad == "truncated":
        other = replace(other, message=other.message[:-1])
    remote_run(obj, first, other)
    snap = obj.snapshot()
    assert not snap.characters.by_id(ALT.hex()).gear.observed
    assert any("Remote items withheld" in w for w in snap.characters.warnings)


def test_identity_and_generation_boundaries_prevent_cross_character_attribution():
    obj = acc()
    obj.observe_frame(roster())
    # Named/portrait evidence only from another connection generation.
    identity(obj)
    obj.observe_event(
        replace(_state_inventory_anchor(timestamp=5, flow_generation=1), opcode=0x14BE)
    )
    obj.observe_frame(counted(wire.ROSTER, [bytes(2) + ALT], when=5.1, generation=1))
    snap = obj.snapshot()
    assert snap.characters.by_id(ACTIVE.hex()) is None
    alt = snap.characters.by_id(ALT.hex())
    assert alt.is_active is None and not alt.main_inventory.observed


def test_character_tables_respect_existing_record_limit():
    obj = acc(capture_limits=ItemStateCaptureLimits(max_snapshot_records=2))
    with pytest.raises(ItemStateCaptureLimitError):
        obj.observe_frame(roster())


@pytest.mark.parametrize("slot,activity", [(53, "hunting"), (54, "farming")])
def test_unverified_knots_are_visible_and_marked_as_inferred(slot, activity):
    obj = acc()
    obj.observe_frame(roster())
    identity(obj)
    row = bytearray(223)
    row[:4] = (123456).to_bytes(4, "little")
    row[4] = 1
    row[221] = slot
    obj.observe_frame(counted(wire.LIFE_GEAR, [row]))
    member = obj.snapshot().characters.by_id(ACTIVE.hex())
    (knot,) = member.life_skills.by_role("knot", activity=activity)
    assert knot.raw_slot == slot
    assert knot.to_dict()["role_inferred"] is True


def test_conflicting_active_names_leave_remote_items_and_withhold_active_tables():
    obj = acc()
    obj.observe_frame(roster())
    identity(obj)
    other_name = bytearray(269)
    other_name[21:29] = ACTIVE
    other_name[113:115] = b"X\0"
    obj.observe_frame(counted(wire.NAMED, [other_name], when=2.01))
    remote_run(obj, counted(wire.REMOTE, [remote(32)]))
    obj.observe_frame(frame(wire.ACTIVE, bytearray(13 + 46 * 221)))
    members = obj.snapshot().characters
    assert members.by_id(ACTIVE.hex()).is_active is None
    assert members.by_id(ACTIVE.hex()).name is None
    assert not members.by_id(ACTIVE.hex()).gear.observed
    assert members.by_id(ALT.hex()).gear.observed


def test_unsupported_profile_returns_character_warning_only_when_requested():
    spec = _inventory_snapshot_spec()
    default = _CharacterStateAccumulator(
        profile_source="test", specs=(spec,)
    ).snapshot()
    assert default.schema_version == 5
    assert default.characters is None and "characters" not in default.to_dict()
    enabled = _CharacterStateAccumulator(
        profile_source="test", specs=(spec,), include_characters=True
    ).snapshot()
    assert enabled.schema_version == 6
    assert enabled.characters.members == () and enabled.characters.warnings
    assert enabled.to_dict()["storages"] == default.to_dict()["storages"]


def test_broken_remote_section_preserves_independently_identified_active_character():
    obj = acc()
    obj.observe_frame(roster())
    identity(obj)
    remote_run(obj, counted(wire.REMOTE, [remote(32), remote(32)]))
    obj.observe_frame(frame(wire.ACTIVE, bytearray(13 + 46 * 221)))
    snapshot = obj.snapshot()
    assert snapshot.characters.status == "available"
    assert snapshot.characters.by_id(ACTIVE.hex()).gear.status == "available"
    assert snapshot.characters.by_id(ALT.hex()).gear.status == "unavailable"
    assert any(
        "Remote items withheld" in warning for warning in snapshot.characters.warnings
    )


@pytest.mark.parametrize("missing", [None, 0, 1, 2, 3, 4])
def test_remote_replacement_requires_both_edges_and_all_pages(missing):
    obj = acc()
    stats_only = bytes.fromhex("3333333333333333")
    unseen = bytes.fromhex("4444444444444444")
    obj.observe_frame(counted(wire.ROSTER, [
        bytes(2) + owner for owner in (ACTIVE, ALT, stats_only, unseen)
    ]))
    identity(obj)
    obj.observe_frame(counted(wire.STATS, [stats_only + bytes(16)]))
    pages = [counted(wire.REMOTE, [remote(slot, code=0)]) for slot in range(3)]
    remote_run(obj, *pages, omit=() if missing is None else (missing,))
    roster = obj.snapshot().characters
    alt = roster.by_id(ALT.hex())
    stats_alt = roster.by_id(stats_only.hex())
    assert not roster.by_id(unseen.hex()).gear.observed
    assert not roster.by_id(ACTIVE.hex()).pearl_inventory.observed
    if missing is None:
        assert len(alt.main_inventory.items) == 3
        assert alt.pearl_inventory.status == stats_alt.gear.status == "available"
        assert not alt.pearl_inventory.items and not stats_alt.gear.items
        assert stats_alt.life_skills.status == "unavailable"
    else:
        assert alt.main_inventory.status == stats_alt.gear.status == "unavailable"
        assert not alt.main_inventory.items
        assert any("Remote items withheld" in w for w in roster.warnings)


def test_remote_fishing_tools_do_not_authorize_replacing_dedicated_life_gear():
    obj = acc()
    obj.observe_frame(roster())
    remote_run(obj, counted(wire.REMOTE, [remote(40)]))
    life = obj.snapshot().characters.by_id(ALT.hex()).life_skills
    assert life.for_activity("fishing")[0].role == "rod"
    assert life.status == "unavailable"
    assert not life.observed
    assert life.observed_sources == ("remote",)


def test_stats_only_owner_not_cleared_if_active_owner_unknown():
    obj = acc()
    obj.observe_frame(roster())
    obj.observe_frame(counted(wire.STATS, [ACTIVE + bytes(16)]))
    remote_run(obj, counted(wire.REMOTE, [remote(32)]))
    members = obj.snapshot().characters
    assert members.by_id(ACTIVE.hex()).is_active is None
    assert members.by_id(ACTIVE.hex()).gear.status == "unavailable"
    assert members.by_id(ALT.hex()).pearl_inventory.status == "available"
