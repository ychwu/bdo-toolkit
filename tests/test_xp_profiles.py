"""XP is an optional portable solo layout, not an identity or event claim."""
from dataclasses import replace
import json

import pytest

from bdo_toolkit import load_opcode_profile, ProfileError
from bdo_toolkit._profile_runtime import validate_runtime_profile
from bdo_toolkit.profiles import XPProfileLayout
from bdo_toolkit.calibration import MessageSpec, update_profile


LAYOUT = XPProfileLayout(0xABCD, 60, 9, 14, 30)


def profile_file(tmp_path):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({"version": 1, "profile_active": True, "specs": {}, "xp": LAYOUT.to_dict()}))
    return path


def test_optional_immutable_layout_roundtrip_and_runtime(tmp_path):
    path = profile_file(tmp_path)
    profile = load_opcode_profile(path)
    assert profile.xp == LAYOUT
    assert profile.to_dict()["xp"] == LAYOUT.to_dict()
    validate_runtime_profile(profile)
    with pytest.raises(AttributeError):
        profile.xp.current_offset = 1
    without = replace(profile, xp=None)
    assert "xp" not in without.to_dict()
    validate_runtime_profile(without)
    with pytest.raises(ProfileError):
        replace(profile, xp={})


@pytest.mark.parametrize("change", [
    {"opcode": True}, {"opcode": 65536}, {"message_length": 21}, {"message_length": 4097},
    {"message_length": 37}, {"level_offset": 14}, {"level_offset": 4}, {"current_offset": 31},
    {"required_offset": 59}, {"flag": False}, {"flag": 1}, {"encoding": "party"},
    {"entity_offset": 40}, {"level_bytes": 4}, {"counter_bytes": 4},
])
def test_invalid_or_unrecognized_layout_rejected(tmp_path, change):
    path = profile_file(tmp_path)
    data = json.loads(path.read_text())
    data["xp"].update(change)
    path.write_text(json.dumps(data))
    with pytest.raises(ProfileError):
        load_opcode_profile(path)


def test_item_update_preserves_xp(tmp_path):
    path = profile_file(tmp_path)
    update_profile([MessageSpec("STORAGE_ITEM_DELTA", 0x1000, 40,
                               item_id_offset=10, quantity_added_offset=14)], path)
    assert load_opcode_profile(path).xp == LAYOUT


def test_remote_fetch_retains_xp_and_rejects_bad_xp_before_install(tmp_path, monkeypatch):
    from bdo_toolkit import fetch_opcode_profile, RemoteProfileError
    from test_remote_profiles import _envelope, _serve
    data = json.loads(profile_file(tmp_path).read_text())
    dest = tmp_path / "fetched.json"
    _serve(monkeypatch, _envelope(data))
    result = fetch_opcode_profile("https://profiles.example.test/v1/current.json", dest)
    assert result.profile.xp == LAYOUT
    before = dest.read_bytes()
    data["xp"]["current_offset"] = 4
    _serve(monkeypatch, _envelope(data))
    with pytest.raises(RemoteProfileError):
        fetch_opcode_profile("https://profiles.example.test/v1/current.json", dest)
    assert dest.read_bytes() == before
