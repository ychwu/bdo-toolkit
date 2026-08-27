"""Current public API contract tests."""

import pytest

from fixture_paths import (
    JULY6_OPCODE_PROFILE,
    JULY17_OPCODE_PROFILE,
    fixture_path,
    has_fixture_pcaps,
)
from bdo_toolkit import (
    AsyncLiveCaptureSession,
    EventFilter,
    LiveCaptureSession,
    capture_live,
    load_opcode_profile,
    replay_pcap,
)
from bdo_toolkit import capture as capture_module
from bdo_toolkit.item_state import CharacterLoadSession, analyze_item_state_pcap
from bdo_toolkit.solare import LiveSolareSession

requires_fixtures = pytest.mark.skipif(
    not has_fixture_pcaps(),
    reason="local pcap fixtures not present (private captures)",
)


def test_tracked_profile_loads_from_explicit_path():
    profile = load_opcode_profile(JULY17_OPCODE_PROFILE)

    assert profile.active
    assert "INVENTORY_TRANSFER" in profile.specs
    assert "STORAGE_ITEM_DELTA" in profile.specs


def test_loaded_profile_is_deeply_immutable_and_serializes_owned_copies():
    profile = load_opcode_profile(JULY17_OPCODE_PROFILE)
    entry = profile.specs["INVENTORY_TRANSFER"][0]

    with pytest.raises(TypeError):
        profile.specs["NEW_EVENT"] = ()
    with pytest.raises(TypeError):
        entry["opcode"] = "0xFFFF"

    payload = profile.to_dict()
    payload["specs"]["INVENTORY_TRANSFER"][0]["opcode"] = "0xFFFF"
    payload["origin_companion_families"][0]["companion_opcodes"][0] = (
        "0xFFFF"
    )

    assert profile.specs["INVENTORY_TRANSFER"][0]["opcode"] == "0x194A"
    assert profile.origin_companion_families[0].companion_opcodes[0] == 0x1A59


@pytest.mark.parametrize(
    "call",
    [
        lambda: load_opcode_profile(),
        lambda: replay_pcap("session.pcapng"),
        lambda: capture_live(),
        lambda: LiveCaptureSession(),
        lambda: AsyncLiveCaptureSession(),
        lambda: analyze_item_state_pcap("character-load.pcapng"),
        lambda: CharacterLoadSession(),
    ],
)
def test_item_decode_apis_require_an_explicit_profile(call):
    with pytest.raises(TypeError, match="opcode_profile|path"):
        call()


def test_loaded_profile_object_is_reused_and_pinned_without_reopening(
    tmp_path,
    monkeypatch,
):
    profile_path = tmp_path / "opcodes.json"
    profile_path.write_bytes(JULY17_OPCODE_PROFILE.read_bytes())
    profile = load_opcode_profile(profile_path)

    def unexpected_reload(_path):
        raise AssertionError("an already-loaded OpcodeProfile must not be reopened")

    monkeypatch.setattr(capture_module, "load_opcode_profile", unexpected_reload)
    collector = capture_module._EventCollector(
        server_ports=(8889,), opcode_profile=profile
    )
    character_session = CharacterLoadSession(opcode_profile=profile)
    profile_path.write_text("{}", encoding="utf-8")

    assert collector.profile_source == f"{profile_path} active profile"
    assert character_session._profile_authority.profile is profile
    collector.finalize()


def test_solare_session_still_requires_no_item_opcode_profile():
    session = LiveSolareSession()

    assert not session.running


@requires_fixtures
def test_replay_batch_storage_deposit_as_structured_events():
    events = list(
        replay_pcap(
            fixture_path("5960_qty1_and_4015_qty1_multi.pcapng"),
            opcode_profile=JULY6_OPCODE_PROFILE,
        )
    )

    assert len(events) == 2
    assert [event.event_type for event in events] == ["storage_delta", "storage_delta"]
    assert [event.storage_name for event in events] == [
        "Heidel",
        "Heidel",
    ]
    assert {event.source for event in events} == {"Worker Production"}
    assert [event.item_id for event in events] == [5960, 4015]
    assert [event.quantity for event in events] == [1, 1]
    assert [event.record_index for event in events] == [1, 2]
    assert [event.record_count for event in events] == [2, 2]
    assert [event.storage_instance for event in events] == [
        "0xb6391c5dcc1b8e00",
        "0xbf8d491bcc1b8e00",
    ]
    first_payload = events[0].to_dict()
    assert first_payload["event_type"] == "storage_delta"
    assert first_payload["quantity"] == 1
    assert first_payload["storage_id"] == 0x0020
    assert first_payload["storage_name"] == "Heidel"
    assert "stream_sequence" in first_payload["extra"]


@requires_fixtures
def test_replay_filters_by_event_type_and_storage_id():
    fixture = fixture_path("5960_qty1_and_4015_qty1_multi.pcapng")

    assert list(
        replay_pcap(
            fixture,
            opcode_profile=JULY6_OPCODE_PROFILE,
            event_filter=EventFilter(event_types={"item_received"}),
        )
    ) == []
    worker_events = list(
        replay_pcap(
            fixture,
            opcode_profile=JULY6_OPCODE_PROFILE,
            event_filter=EventFilter(storage_ids={0x0020}),
        )
    )
    assert len(worker_events) == 2
    assert len(
        list(
            replay_pcap(
                fixture,
                opcode_profile=JULY6_OPCODE_PROFILE,
                event_filter=EventFilter(
                    event_types={"storage_delta"},
                    sources={"Worker Production"},
                    storage_ids={0x0020},
                ),
            )
        )
    ) == 2
    assert list(
        replay_pcap(
            fixture,
            opcode_profile=JULY6_OPCODE_PROFILE,
            event_filter=EventFilter(item_ids={5960}),
        )
    )[0].item_id == 5960


@requires_fixtures
def test_manual_bulk_deposit_uses_destination_storage_label():
    events = list(
        replay_pcap(
            fixture_path("1000306_qty5_unstackable_i2s.pcapng"),
            opcode_profile=JULY6_OPCODE_PROFILE,
        )
    )

    assert len(events) == 5
    assert {event.storage_name for event in events} == {"Heidel"}
    assert {event.source for event in events} == {"Player Inventory"}
    assert [event.record_index for event in events] == [1, 2, 3, 4, 5]

