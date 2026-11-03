from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from contextlib import nullcontext
import json

import pytest
from bdo_toolkit.character_calibration import (
    _calibrate,
    calibrate_character_layout_live,
)
from bdo_toolkit._item_state.character_profile import NOVEMBER, CharacterLayoutProfile
from bdo_toolkit._item_state.character_witnesses import Witnesses
from bdo_toolkit.events import Flow
from bdo_toolkit.raw import RawMessage
from bdo_toolkit.item_state import CharacterLoadSession, analyze_item_state_pcap
from fixture_paths import JULY17_OPCODE_PROFILE


def synthetic_login():
    ids = [sha256(f"anon {i}".encode()).digest()[:8] for i in range(9)]
    frames = []

    def send(op, header, count_pos, rows):
        data = bytearray(header)
        data[3:5] = op.to_bytes(2, "little")
        data[count_pos : count_pos + 2] = len(rows).to_bytes(2, "little")
        data.extend(b"".join(rows))
        data[:2] = len(data).to_bytes(2, "little")
        frames.append(
            RawMessage(
                bytes(data),
                1.0,
                Flow("1", 8889, "2", 1000),
                1,
                len(frames),
                len(frames) * 65536,
            )
        )

    send(
        501,
        7,
        5,
        [
            v.to_bytes(2, "little") + owner
            for owner, v in zip(ids, [1, 3, 2, 65535, 0, 5, 65535, 4, 9])
        ],
    )
    send(502, 13, 8, [bytes(16) + owner for owner in ids])
    send(503, 10, 8, [owner + bytes(16) for owner in ids[:-1]])
    remote = []
    for i in range(120):
        row = bytearray(73)
        row[42] = i % 15
        code = (0, 1, 17)[i % 3]
        row[72] = code
        row[64:72] = ids[i // 15]
        row[60:64] = (100_100 + i * 173).to_bytes(4, "little")
        row[4:12] = (1 if code == 1 else i + 1).to_bytes(8, "little")
        remote.append(row)
    send(504, 14, 8, remote[:70])
    send(504, 14, 8, remote[70:])
    return frames


def test_live_discovers_rotated_opcodes_without_reference(monkeypatch, tmp_path):
    frames = synthetic_login()
    session = SimpleNamespace(events=lambda: iter(frames), error=None)
    monkeypatch.setattr(
        "bdo_toolkit.character_calibration.LiveRawSession",
        lambda **kwargs: nullcontext(session),
    )
    result = calibrate_character_layout_live(capture_seconds=1)
    assert result.profile is not None
    assert result.profile.tables["remote"].opcode == 504
    assert result.profile.tables["remote"].fields["owner"] == 64
    assert "active" not in result.profile.tables
    path = tmp_path / "new.characters.json"
    result.profile.save(path)
    assert CharacterLayoutProfile.load(path) == result.profile
    with pytest.raises(FileExistsError):
        result.profile.save(path)
    assert CharacterLayoutProfile.load(path) == result.profile


def test_missing_corroborating_family_rejects_calibration():
    result = _calibrate(
        [f for f in synthetic_login() if f.opcode != 502], NOVEMBER, Witnesses()
    )
    assert result.profile is None


@pytest.mark.parametrize("extra_slot, expect_sockets", [(27, True), (6, False)])
def test_remote_socket_discovery_with_other_equipped_data(extra_slot, expect_sockets):
    from dataclasses import replace
    import struct

    frames = synthetic_login()
    message = bytearray(frames[-2].message)
    for index, slot, pair in [
        (1, 32, (760002, 762001)),
        (4, 33, (760010, 760001)),
        (7, extra_slot, (750000, 0)),
    ]:
        start = 14 + index * 73
        message[start + 42] = slot
        struct.pack_into("<II", message, start + 26, *pair)
    frames[-2] = replace(frames[-2], message=bytes(message))
    profile = _calibrate(frames, NOVEMBER, Witnesses()).profile
    assert profile is not None
    fields = profile.tables["remote"].fields
    assert (fields.get("stone1"), fields.get("stone2")) == (
        (26, 30) if expect_sockets else (None, None)
    )


def test_incompatible_field_offsets_rejected(tmp_path):
    data = NOVEMBER.to_dict()
    data["tables"]["remote"]["fields"]["quantity"] = 64
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="span"):
        CharacterLayoutProfile.load(path)


def test_default_replay_reports_unavailable_and_still_returns_other_sections(
    monkeypatch, tmp_path
):
    from bdo_toolkit._item_state import session as module

    monkeypatch.setattr(module, "iter_pcap_file", lambda *args: ())
    profile = tmp_path / "opcodes.local"
    profile.write_bytes(JULY17_OPCODE_PROFILE.read_bytes())
    side = Path(str(profile) + ".characters.json")
    side.write_text('{"schema_version":999}')
    result = analyze_item_state_pcap("unused", opcode_profile=profile)
    assert result.characters.status == "unavailable"
    assert "profile unavailable" in result.characters.warnings[0].lower()
    assert result.to_dict()["inventory"] == result.inventory.to_dict()
    assert "storages" in result.to_dict()
    legacy = analyze_item_state_pcap(
        "unused", opcode_profile=profile, include_characters=False
    )
    assert legacy.characters is None and legacy.schema_version == 5


def test_previous_layout_can_be_checked_with_one_chunk():
    frames = synthetic_login()
    previous = _calibrate(frames, NOVEMBER, Witnesses()).profile
    assert previous is not None
    from dataclasses import replace

    data = bytearray(frames[-2].message + frames[-1].message[14:])
    data[:2] = len(data).to_bytes(2, "little")
    data[8:10] = (120).to_bytes(2, "little")
    single = frames[:-2] + [replace(frames[-2], message=bytes(data))]
    assert _calibrate(single, NOVEMBER, Witnesses()).profile is None
    carried = _calibrate(single, previous, Witnesses())
    assert carried.profile == previous


def test_competing_remote_families_do_not_produce_a_profile():
    from dataclasses import replace

    frames = synthetic_login()
    copies = []
    for frame in frames:
        if frame.opcode == 504:
            data = bytearray(frame.message)
            data[3:5] = (505).to_bytes(2, "little")
            copies.append(replace(frame, message=bytes(data)))
    assert _calibrate(frames + copies, NOVEMBER, Witnesses()).profile is None


def test_overwrite_refuses_non_character_profile(tmp_path):
    path = tmp_path / "opcodes.local"
    path.write_bytes(JULY17_OPCODE_PROFILE.read_bytes())
    with pytest.raises(ValueError):
        NOVEMBER.save(path, overwrite=True)
    assert path.read_bytes() == JULY17_OPCODE_PROFILE.read_bytes()


def test_embedded_layout_precedence_and_isolated_failure(tmp_path):
    from bdo_toolkit._item_state.session import _resolve_character_profile
    from bdo_toolkit.profiles import load_opcode_profile

    path = tmp_path / "opcodes.local"
    data = {"version": 1, "profile_active": True}
    path.write_text(json.dumps(data))
    NOVEMBER.save(Path(str(path) + ".characters.json"))
    assert _resolve_character_profile(None, load_opcode_profile(path), True) == (NOVEMBER, None)
    core = CharacterLayoutProfile({k: NOVEMBER.tables[k] for k in ("roster", "remote")})
    data["characters"] = core.to_dict()
    path.write_text(json.dumps(data))
    assert _resolve_character_profile(None, load_opcode_profile(path), True) == (core, None)
    data["characters"] = {"schema_version": 999}
    path.write_text(json.dumps(data))
    profile = load_opcode_profile(path)
    assert _resolve_character_profile(None, profile, True) == (None, profile.character_profile_error)
    assert profile.character_profile_error
    assert _resolve_character_profile(NOVEMBER, profile, True) == (NOVEMBER, None)


def test_character_cli_updates_only_combined_section(tmp_path, monkeypatch):
    from bdo_toolkit.cli import main
    from bdo_toolkit.profiles import load_opcode_profile
    from bdo_toolkit.character_calibration import _previous

    monkeypatch.chdir(tmp_path)
    path = tmp_path / "opcodes.local"
    side = Path(str(path) + ".characters.json")
    NOVEMBER.save(side)
    result = _calibrate(synthetic_login(), NOVEMBER, Witnesses())
    assert result.profile

    def replay(_pcap, *, previous_profile, **kwargs):
        assert _previous(previous_profile) == NOVEMBER
        return result

    monkeypatch.setattr("bdo_toolkit.character_calibration.calibrate_character_layout_pcap", replay)
    args = ["character-calibrate", "--pcap", "login.pcap"]
    assert main(args) == 0
    assert load_opcode_profile(path).characters == result.profile

    data = json.loads(JULY17_OPCODE_PROFILE.read_text(encoding="utf-8-sig"))
    data["custom_metadata"] = {"keep": True}
    path.write_text(json.dumps(data))
    original = path.read_bytes()
    assert main([*args, "--profile", str(path)]) == 0
    assert json.loads(path.read_bytes()) == {**data, "characters": result.profile.to_dict()}
    assert next((tmp_path / "opcodes_backups").iterdir()).read_bytes() == original
    assert CharacterLayoutProfile.load(side) == NOVEMBER
    before = path.read_bytes()
    failure = _calibrate([], NOVEMBER, Witnesses())
    monkeypatch.setattr("bdo_toolkit.character_calibration.calibrate_character_layout_pcap",
                        lambda *args, **kwargs: failure)
    assert main(args) == 2
    assert path.read_bytes() == before
