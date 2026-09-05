"""Current public API contract tests."""


import pytest

from fixture_paths import (
    JULY17_OPCODE_PROFILE,
    JULY6_OPCODE_PROFILE,
    fixture_path,
    has_fixture_pcaps,
)

from bdo_toolkit import (
    AsyncLiveCaptureSession,
    BDOEvent,
    EventFilter,
    Flow,
    LiveCaptureSession,
    capture as capture_module,
    capture_live,
    load_opcode_profile,
    replay_pcap,
)
from bdo_toolkit.item_state import CharacterLoadSession, analyze_item_state_pcap
from bdo_toolkit.solare import LiveSolareSession


requires_fixtures = pytest.mark.skipif(
    not has_fixture_pcaps(),
    reason="local pcap fixtures not present (private captures)",
)


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
            fixture_path('storage--worker-two-item-deposit--de2d86c32a'),
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
    fixture = fixture_path('storage--worker-two-item-deposit--de2d86c32a')

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
            fixture_path('storage--manual-unstackable-batch--46b846b370'),
            opcode_profile=JULY6_OPCODE_PROFILE,
        )
    )

    assert len(events) == 5
    assert {event.storage_name for event in events} == {"Heidel"}
    assert {event.source for event in events} == {"Player Inventory"}
    assert [event.record_index for event in events] == [1, 2, 3, 4, 5]


def test_event_extra_is_deeply_immutable_hashable_and_json_safe():
    original = {"nested": {"values": [1, 2]}, "_vendor": "preserved"}
    event = BDOEvent("test", 0.0, Flow("a", 1, "b", 2), 1, 1, extra=original)
    original["nested"]["values"].append(3)

    with pytest.raises(TypeError):
        event.extra["new"] = True
    with pytest.raises(TypeError):
        event.extra["nested"]["new"] = True
    assert hash(event) == hash(event)
    assert event.to_dict()["extra"] == {
        "nested": {"values": [1, 2]},
        "_vendor": "preserved",
    }
    assert event.to_dict()["timestamp_iso"] == "1970-01-01T00:00:00.000Z"


def test_filter_rejects_accidental_string_iterables():
    with pytest.raises(TypeError, match="not a string"):
        EventFilter.from_values(sources="Mob Drop")


def test_event_filter_constructor_normalizes_and_freezes_inputs():
    sources = {"Mob Drop"}
    storage_ids = {0x0020}
    event_filter = EventFilter(sources=sources, storage_ids=storage_ids)
    sources.add("Storage")
    storage_ids.add(0x0058)

    assert event_filter.sources == frozenset({"Mob Drop"})
    assert event_filter.storage_ids == frozenset({0x0020})
