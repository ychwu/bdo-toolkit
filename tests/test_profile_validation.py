"""Explicit profile authority and runtime layout validation."""

from __future__ import annotations

import json

import pytest

from bdo_toolkit import ProfileError, load_opcode_profile, replay_pcap
from bdo_toolkit._framing import TargetMessageScanner
from bdo_toolkit._protocol import FlowKey, PacketContext
from bdo_toolkit._specs import event_specs_from_profile
from bdo_toolkit.calibration import MessageSpec, update_profile


def test_missing_explicit_profile_does_not_silently_fall_back(tmp_path):
    events = replay_pcap(
        tmp_path / "capture.pcapng",
        opcode_profile=tmp_path / "typo.json",
    )
    with pytest.raises(FileNotFoundError, match="Opcode profile"):
        next(events)


def test_inactive_explicit_profile_fails_instead_of_mixing_authorities(tmp_path):
    profile_path = tmp_path / "inactive.json"
    profile_path.write_text(
        json.dumps({"version": 1, "profile_active": False, "specs": {}}),
        encoding="utf-8",
    )

    assert load_opcode_profile(profile_path).active is False
    events = replay_pcap("unused.pcapng", opcode_profile=profile_path)
    with pytest.raises(ProfileError, match="inactive"):
        next(events)


def test_runtime_profile_preserves_distinct_same_opcode_layouts(tmp_path):
    profile_path = tmp_path / "opcodes.json"
    first = MessageSpec(
        "STORAGE_ITEM_DELTA",
        0x126D,
        257,
        item_id_offset=36,
        quantity_added_offset=40,
        context_offset=27,
        destination_instance_offset=71,
        repeat_stride=222,
    )
    second = MessageSpec(
        "STORAGE_ITEM_DELTA",
        0x126D,
        260,
        item_id_offset=36,
        quantity_added_offset=40,
        context_offset=27,
        destination_instance_offset=71,
        repeat_stride=225,
    )

    update_profile([first, second], profile_path, backup=False)
    loaded = event_specs_from_profile(load_opcode_profile(profile_path))

    assert len(loaded.specs) == 2
    assert {
        (
            spec.min_message_length,
            spec.single_record_message_length,
            spec.repeat_stride,
        )
        for spec in loaded.specs
    } == {
        (257, 257, 222),
        (260, 260, 225),
    }


def test_runtime_loot_profile_preserves_disjoint_length_variants(tmp_path):
    profile_path = tmp_path / "opcodes.json"
    payload = {
        "version": 1,
        "profile_active": True,
        "specs": {
            "LOOT_PREVIEW": [
                {
                    "event": "LOOT_PREVIEW",
                    "opcode": "0x1643",
                    "length": 244,
                    "item_id_offset": 23,
                    "quantity_offset": 27,
                    "item_instance_offset": 58,
                },
                {
                    "event": "LOOT_PREVIEW",
                    "opcode": "0x1643",
                    "length": 252,
                    "item_id_offset": 23,
                    "quantity_offset": 27,
                    "item_instance_offset": 66,
                },
            ]
        },
    }
    profile_path.write_text(json.dumps(payload), encoding="utf-8")

    loaded = event_specs_from_profile(load_opcode_profile(profile_path))

    assert len(loaded.specs) == 2
    assert {
        (spec.item_instance_offset, spec.single_record_message_length)
        for spec in loaded.specs
    } == {(58, 244), (66, 252)}

    events = []
    scanner = TargetMessageScanner(
        lambda event, _raw: events.append(event),
        loaded.specs,
    )
    context = PacketContext(
        timestamp=1.0,
        flow=FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000),
    )
    for length, instance_offset, instance in (
        (244, 58, bytes.fromhex("0102030405060708")),
        (252, 66, bytes.fromhex("1112131415161718")),
    ):
        message = bytearray(length)
        message[0:2] = length.to_bytes(2, "little")
        message[3:5] = (0x1643).to_bytes(2, "little")
        message[23:27] = (7003).to_bytes(4, "little")
        message[27:31] = (3).to_bytes(4, "little")
        message[instance_offset : instance_offset + 8] = instance
        scanner.scan_standalone(bytes(message), context)

    assert [
        (event.message_length, event.item_instance) for event in events
    ] == [
        (244, bytes.fromhex("0102030405060708")),
        (252, bytes.fromhex("1112131415161718")),
    ]


def test_runtime_loot_profile_rejects_overlapping_instance_only_variants(
    tmp_path,
):
    profile_path = tmp_path / "opcodes.json"
    payload = {
        "version": 1,
        "profile_active": True,
        "specs": {
            "LOOT_PREVIEW": [
                {
                    "event": "LOOT_PREVIEW",
                    "opcode": "0x1643",
                    "length": 244,
                    "item_id_offset": 23,
                    "quantity_offset": 27,
                    "item_instance_offset": 58,
                },
                {
                    "event": "LOOT_PREVIEW",
                    "opcode": "0x1643",
                    "length": 244,
                    "item_id_offset": 23,
                    "quantity_offset": 27,
                    "item_instance_offset": 66,
                },
            ]
        },
    }
    profile_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(
        ProfileError,
        match=r"Ambiguous LOOT_PREVIEW.*0x1643.*58.*66",
    ):
        event_specs_from_profile(load_opcode_profile(profile_path))


@pytest.mark.parametrize(
    "second_layout",
    (
        {
            "length": None,
            "item_id_offset": 23,
            "quantity_offset": 27,
            "item_instance_offset": 58,
        },
        {
            "length": 244,
            "item_id_offset": 33,
            "quantity_offset": 37,
            "item_instance_offset": 68,
        },
    ),
    ids=("exact-and-open-length", "different-record-offsets"),
)
def test_runtime_loot_profile_rejects_every_overlapping_opcode_layout(
    tmp_path,
    second_layout,
):
    profile_path = tmp_path / "opcodes.json"
    second = {
        "event": "LOOT_PREVIEW",
        "opcode": "0x1643",
        **second_layout,
    }
    payload = {
        "version": 1,
        "profile_active": True,
        "specs": {
            "LOOT_PREVIEW": [
                {
                    "event": "LOOT_PREVIEW",
                    "opcode": "0x1643",
                    "length": 244,
                    "item_id_offset": 23,
                    "quantity_offset": 27,
                    "item_instance_offset": 58,
                },
                second,
            ]
        },
    }
    profile_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(
        ProfileError,
        match=r"Ambiguous LOOT_PREVIEW.*overlapping runtime message-length",
    ):
        event_specs_from_profile(load_opcode_profile(profile_path))


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"version": 1, "profile_active": "false", "specs": {}},
        {"version": "one", "specs": {}},
        {"version": 1, "specs": {"INVENTORY_TRANSFER": {}}},
        {
            "version": 1,
            "specs": {
                "INVENTORY_TRANSFER": [
                    {"event": "LOOT_PREVIEW", "opcode": "0x1234"}
                ]
            }
        },
        {
            "version": 1,
            "specs": {},
            "origin_companion_families": [
                {
                    "detection": "opcode-only",
                    "delta_opcode": "0x0D7E",
                    "companion_opcodes": ["0x0F7E", "0x0DE1"],
                    "companion_lengths": [60, 23],
                    "observations": 2,
                }
            ],
        },
        {
            "version": 1,
            "specs": {
                "STORAGE_ITEM_DELTA": [
                    {
                        "event": "STORAGE_ITEM_DELTA",
                        "opcode": "0x1234",
                        "length": 100,
                        "item_id_offset": 20,
                        "quantity_added_offset": 24,
                        "destination_instance_offset": 55,
                        "context_offset": 18,
                        "record_count_offset": 6,
                    }
                ]
            }
        },
        {
            "version": 1,
            "specs": {
                "STORAGE_ITEM_DELTA": [
                    {
                        "event": "STORAGE_ITEM_DELTA",
                        "opcode": "0x1234",
                        "length": 100,
                        "item_id_offset": 20,
                        "quantity_added_offset": 24,
                        "destination_instance_offset": 55,
                        "context_offset": 8,
                        "record_count_offset": 19,
                    }
                ]
            }
        },
    ],
)
def test_malformed_profiles_raise_public_profile_error(tmp_path, payload):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProfileError):
        load_opcode_profile(path)


@pytest.mark.parametrize(
    "payload",
    [
        {"profile_active": True, "specs": {}},
        {"version": 2, "profile_active": True, "specs": {}},
    ],
    ids=("missing-version", "unsupported-version"),
)
def test_profile_requires_exact_schema_version_one(tmp_path, payload):
    path = tmp_path / "unsupported-version.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProfileError, match=r"version.*must be 1"):
        load_opcode_profile(path)
