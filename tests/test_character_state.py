from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from bdo_toolkit import PacketCaptureOptions
from bdo_toolkit import _capture_runtime as capture_runtime
from bdo_toolkit import capture as capture_module
from bdo_toolkit import character_state as character_state_module
from bdo_toolkit.character_state import (
    CharacterLoadSession,
    ItemStateCaptureLimitError,
    ItemStateCaptureLimits,
    _CharacterStateAccumulator,
    analyze_character_load_pcap,
    format_character_state,
)
from bdo_toolkit._protocol import (
    BDOFrame,
    CHARACTER_LOAD_CONTEXT,
    EventSpec,
    FlowKey,
    LootEvent,
    PacketContext,
)
from bdo_toolkit.events import BDOEvent, Flow
from bdo_toolkit.diagnostics import DecoderHealth
from fixture_paths import JULY17_OPCODE_PROFILE, fixture_path, has_fixture_pcaps

requires_fixtures = pytest.mark.skipif(
    not has_fixture_pcaps(), reason="private packet fixtures are not available"
)


def _inventory_diagnostics(state):
    assert state.diagnostics is not None
    return state.diagnostics.inventory


def _storage_diagnostics(state, storage_id: int):
    assert state.diagnostics is not None
    diagnostic = state.diagnostics.storage.destination(storage_id)
    assert diagnostic is not None
    return diagnostic


@requires_fixtures
def test_july17_character_state_report_recovers_inventory_and_storage():
    try:
        capture = fixture_path("fullcapture.pcapng")
    except FileNotFoundError:
        pytest.skip("July 17 private initial-load fixture not present")
    profile = JULY17_OPCODE_PROFILE

    state = analyze_character_load_pcap(capture, opcode_profile=profile)

    assert state.hydration_detected
    assert state.provenance.capture_mode == "pcap_replay"
    assert state.provenance.capture_path == str(capture)
    assert state.diagnostics is not None
    inventory_diagnostics = _inventory_diagnostics(state)
    assert inventory_diagnostics.generations_observed == 1
    assert state.identity_complete
    assert state.coverage.inventory_records_missing_instance == 0
    assert state.coverage.storage_records_missing_instance == 0
    assert state.decoder_health.storage_status == "compatible"
    assert state.decoder_health.storage_is_compatible is True
    assert (
        state.decoder_health.storage_messages_decoded
        == state.decoder_health.storage_messages_observed
        > 0
    )
    assert state.diagnostics.snapshot_records_retained == 2_727
    assert inventory_diagnostics.raw_records == 247
    assert state.inventory.serialized_records == 247
    assert state.inventory.occupied_stacks == 243
    assert state.inventory.currency_balance_records == 4
    assert state.inventory.unclassified_records == 0
    assert inventory_diagnostics.group_counts == (72, 2, 72, 70, 2, 0, 29, 0)
    assert inventory_diagnostics.populated_groups == 6
    assert inventory_diagnostics.empty_groups == 2
    assert inventory_diagnostics.inferred_strides == (223,)
    assert inventory_diagnostics.source_opcodes
    assert inventory_diagnostics.message_lengths

    main = state.inventory.container(0x00)
    pearl = state.inventory.container_named("pearl inventory")
    currencies = state.inventory.container(0x18)
    enhancement = state.inventory.container(0x0B)
    assert main is not None and main.occupied_stacks == 74
    assert pearl is not None and pearl.occupied_stacks == 140
    assert pearl.serialized_records == 142
    assert currencies is not None and currencies.occupied_stacks == 0
    assert currencies.serialized_records == 2
    assert enhancement is not None and enhancement.occupied_stacks == 29
    assert all(
        container.confidence == "provisional"
        for container in state.inventory.containers
    )
    assert state.inventory.currency("Silver").quantity == 1_832_291_219
    assert state.inventory.currency(6).quantity == 363
    assert state.inventory.currency("Loyalties").quantity == 17_600
    assert state.inventory.currency(10).quantity == 105_742

    # Two repeated storage sweeps produce 2,480 decoded records but describe
    # one 1,240-stack state. Four explicit empty envelopes complete all 33
    # registered destinations in the second sweep.
    assert state.diagnostics.storage.records_decoded == 2480
    assert state.storages.occupied_stacks == 1240
    assert state.storages.registered_count == 33
    assert state.storages.nonempty_count == 29
    assert state.storages.empty_count == 4

    heidel = state.storages.by_id(0x0020)
    assert heidel is not None
    assert heidel.name == "Heidel"
    assert heidel.occupied_stacks == 184
    heidel_diagnostics = _storage_diagnostics(state, heidel.storage_id)
    assert heidel_diagnostics.raw_records == 368
    assert heidel_diagnostics.duplicate_records == 184
    assert heidel_diagnostics.source_opcodes
    assert heidel_diagnostics.message_lengths
    assert state.storages.named("heidel") == heidel

    output = format_character_state(state)
    assert (
        "247 serialized records: 243 occupied item stacks + 4 currency balances"
        in output
    )
    assert "6 populated, 2 empty" in output
    assert "33/34 known destinations observed" in output
    assert "29 non-empty, 4 explicitly empty, 1 not observed" in output
    assert "known destinations not observed: Angavu Outpost" in output
    assert "Heidel: 184 occupied item stacks detected" in output
    assert "capacity: unavailable" in output
    assert "Main Inventory [0x00, provisional]: 74 item stacks" in output
    assert "2 empty wrappers: unclassified" in output
    assert "Silver: 1,832,291,219" in output
    assert "/192" not in output
    assert "initial login vs character switch" in output


@requires_fixtures
def test_july17_character_switch_classifies_exact_inventory_state():
    try:
        capture = fixture_path("character-switch-2026-07-17-01.pcapng")
    except FileNotFoundError:
        pytest.skip("July 17 private character-switch fixture not present")
    profile = JULY17_OPCODE_PROFILE

    state = analyze_character_load_pcap(capture, opcode_profile=profile)
    inventory = state.inventory
    inventory_diagnostics = _inventory_diagnostics(state)

    assert inventory_diagnostics.raw_records == 246
    assert inventory.serialized_records == 246
    assert inventory.occupied_stacks == 242
    assert inventory.currency_balance_records == 4
    assert inventory_diagnostics.group_counts == (72, 1, 72, 70, 2, 0, 29, 0)
    assert inventory_diagnostics.inferred_strides == (223,)
    assert inventory.unclassified_records == 0

    assert state.hydration_detected
    assert state.diagnostics is not None
    assert inventory_diagnostics.generations_observed == 1
    assert state.identity_complete
    assert state.coverage.inventory_records_missing_instance == 0
    assert state.coverage.storage_records_missing_instance == 0
    assert state.diagnostics.snapshot_records_retained == 2_730
    assert state.diagnostics.storage.records_decoded == 2_484
    assert state.storages.occupied_stacks == 1_242
    assert state.storages.registered_count == 33
    assert state.storages.nonempty_count == 29
    assert state.storages.empty_count == 4

    heidel = state.storages.named("Heidel")
    assert heidel is not None
    heidel_diagnostics = _storage_diagnostics(state, heidel.storage_id)
    assert (
        heidel_diagnostics.raw_records,
        heidel.occupied_stacks,
        heidel_diagnostics.duplicate_records,
        heidel_diagnostics.groups,
    ) == (366, 183, 183, 6)

    # One retransmitted Old Wisdom Tree frame must not create a third group.
    old_wisdom = state.storages.named("Old Wisdom Tree")
    assert old_wisdom is not None
    old_wisdom_diagnostics = _storage_diagnostics(state, old_wisdom.storage_id)
    assert old_wisdom.occupied_stacks == 13
    assert old_wisdom_diagnostics.groups == 2

    bukpo = state.storages.named("Bukpo")
    assert bukpo is not None
    bukpo_diagnostics = _storage_diagnostics(state, bukpo.storage_id)
    assert bukpo_diagnostics.raw_records == 0
    assert bukpo.occupied_stacks == 0
    assert bukpo_diagnostics.empty_envelope_seen

    assert [
        (
            container.raw_code,
            container.name,
            container.confidence,
            container.occupied_stacks,
            len(container.currency_balances),
        )
        for container in inventory.containers
    ] == [
        (0x00, "Main Inventory", "provisional", 73, 0),
        (0x10, "Pearl Inventory", "provisional", 140, 2),
        (0x18, "Global Currencies", "provisional", 0, 2),
        (0x0B, "Enhancement Inventory", "provisional", 29, 0),
    ]
    assert {
        balance.item_id: (
            balance.currency_name,
            balance.quantity,
            balance.inventory_slot,
            balance.container_code,
        )
        for balance in inventory.currency_balances
    } == {
        1: ("Silver", 1_832_291_219, 3, 0x18),
        6: ("Pearl", 363, 0, 0x10),
        7: ("Loyalties", 17_900, 1, 0x10),
        10: ("Crow Coin", 105_742, 0, 0x18),
    }

    # The one-record second main-inventory wrapper uses a stride learned from
    # its multi-record siblings and still receives validated metadata.
    singleton_item = inventory.records_for(44_391)
    assert len(singleton_item) == 1
    assert singleton_item[0].inventory_slot == 122
    assert singleton_item[0].container_code == 0x00
    assert singleton_item[0].container_name == "Main Inventory"

    payload = state.to_dict()["inventory"]
    assert isinstance(payload, dict)
    assert payload["serialized_records"] == 246
    assert payload["currency_balance_records"] == 4
    assert payload["unclassified_records"] == 0
    assert "containers" not in payload
    serialized_main_item = next(
        item for item in payload["items"] if item["container_code"] == 0x00
    )
    assert serialized_main_item["container_code_hex"] == "0x00"
    main_payload = inventory.containers[0].to_dict()
    assert main_payload["raw_code"] == 0x00
    assert main_payload["raw_code_hex"] == "0x00"


def _synthetic_inventory_tail_group(
    *,
    sequence: int,
    stride: int,
    slot_relative: int,
    container_relative: int,
    container_code: int,
    count: int = 3,
    slot_start: int = 2,
    item_id_start: int = 7003,
    decoy_slot_relative: int | None = None,
    decoy_container_relative: int | None = None,
) -> tuple[BDOFrame, list[BDOEvent], EventSpec, int]:
    item_offset = 31
    base_length = item_offset + stride
    message_length = base_length + (count - 1) * stride
    message = bytearray(message_length)
    message[:2] = message_length.to_bytes(2, "little")
    message[3:5] = (0x194A).to_bytes(2, "little")
    message[27:31] = CHARACTER_LOAD_CONTEXT
    flow_key = FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000)
    flow = Flow("10.0.0.1", 8889, "10.0.0.2", 50000)
    records: list[BDOEvent] = []
    for index in range(count):
        record_offset = item_offset + index * stride
        message[record_offset + slot_relative] = slot_start + index
        message[record_offset + container_relative] = container_code
        if decoy_slot_relative is not None:
            message[record_offset + decoy_slot_relative] = 20 + index
        if decoy_container_relative is not None:
            message[record_offset + decoy_container_relative] = container_code
        records.append(
            BDOEvent(
                event_type="inventory_snapshot",
                timestamp=float(sequence),
                flow=flow,
                item_id=item_id_start + index,
                quantity=1,
                opcode=0x194A,
                message_length=message_length,
                item_instance=f"instance-{sequence}-{index}",
                record_index=index + 1,
                record_count=count,
                record_offset=record_offset,
                extra={"stream_sequence": sequence},
            )
        )
    frame = BDOFrame(
        index=sequence,
        message=bytes(message),
        context=PacketContext(
            timestamp=float(sequence),
            flow=flow_key,
            stream_start=sequence,
        ),
        stream_sequence=sequence,
    )
    spec = EventSpec(
        label="INVENTORY_TRANSFER",
        opcode=0x194A,
        item_offset=item_offset,
        quantity_offset=item_offset + 4,
        min_message_length=base_length,
        source_context_offset=27,
        item_instance_offset=66,
        single_record_message_length=base_length,
    )
    return frame, records, spec, stride


def test_inventory_tail_layout_is_discovered_for_prior_observed_geometry():
    groups = [
        _synthetic_inventory_tail_group(
            sequence=100 + code,
            stride=228,
            slot_relative=221,
            container_relative=224,
            container_code=code,
        )
        for code in (0x00, 0x0B)
    ]

    layout = character_state_module._discover_inventory_tail_layout(groups)

    assert layout == (221, 224)
    frame, records, spec, stride = groups[1]
    metadata = character_state_module._inventory_record_metadata(
        frame,
        records,
        spec,
        stride,
        layout,
    )
    assert metadata is not None
    assert [metadata[event.record_offset].slot for event in records] == [2, 3, 4]
    assert {metadata[event.record_offset].container_code for event in records} == {0x0B}


def test_inventory_tail_layout_is_discovered_when_container_precedes_slot():
    groups = [
        _synthetic_inventory_tail_group(
            sequence=150 + code,
            stride=226,
            slot_relative=225,
            container_relative=224,
            container_code=code,
        )
        for code in (0x00, 0x0B)
    ]

    layout = character_state_module._discover_inventory_tail_layout(groups)

    assert layout == (225, 224)
    frame, records, spec, stride = groups[1]
    metadata = character_state_module._inventory_record_metadata(
        frame,
        records,
        spec,
        stride,
        layout,
    )
    assert metadata is not None
    assert [metadata[event.record_offset].slot for event in records] == [2, 3, 4]
    assert {metadata[event.record_offset].container_code for event in records} == {0x0B}


def test_reversed_inventory_tail_layout_is_reused_for_single_currency_record():
    groups = [
        _synthetic_inventory_tail_group(
            sequence=170 + code,
            stride=226,
            slot_relative=225,
            container_relative=224,
            container_code=code,
        )
        for code in (0x00, 0x0B)
    ]
    groups.append(
        _synthetic_inventory_tail_group(
            sequence=190,
            stride=226,
            slot_relative=225,
            container_relative=224,
            container_code=0x18,
            count=1,
            slot_start=9,
            item_id_start=1,
        )
    )
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(groups[0][2],),
    )

    assembly = accumulator._inventory_summary(
        tuple(frame for frame, _, _, _ in groups),
        tuple(event for _, records, _, _ in groups for event in records),
        generations_observed=1,
    )
    summary = assembly.summary

    assert summary.unclassified_records == 0
    assert summary.container(0x00).occupied_stacks == 3
    assert summary.container(0x0B).occupied_stacks == 3
    assert summary.currency_balance_records == 1
    silver = summary.currency("Silver")
    assert silver is not None
    assert silver.inventory_slot == 9


def test_inventory_tail_layout_fails_closed_when_slot_column_is_ambiguous():
    groups = [
        _synthetic_inventory_tail_group(
            sequence=200 + code,
            stride=223,
            slot_relative=221,
            container_relative=222,
            container_code=code,
            decoy_slot_relative=220,
        )
        for code in (0x00, 0x10)
    ]

    assert character_state_module._discover_inventory_tail_layout(groups) is None


def test_inventory_tail_layout_fails_closed_when_container_side_is_ambiguous():
    groups = [
        _synthetic_inventory_tail_group(
            sequence=250 + code,
            stride=223,
            slot_relative=221,
            container_relative=222,
            container_code=code,
            decoy_container_relative=220,
        )
        for code in (0x00, 0x10)
    ]

    assert character_state_module._discover_inventory_tail_layout(groups) is None


def test_inventory_tail_layout_fails_closed_for_an_unknown_container_code():
    groups = [
        _synthetic_inventory_tail_group(
            sequence=300 + code,
            stride=223,
            slot_relative=221,
            container_relative=222,
            container_code=code,
        )
        for code in (0x00, 0x42)
    ]

    assert character_state_module._discover_inventory_tail_layout(groups) is None


def test_reversed_inventory_tail_layout_fails_closed_for_unknown_container_code():
    groups = [
        _synthetic_inventory_tail_group(
            sequence=320 + code,
            stride=226,
            slot_relative=225,
            container_relative=224,
            container_code=code,
        )
        for code in (0x00, 0x42)
    ]

    assert character_state_module._discover_inventory_tail_layout(groups) is None


def _synthetic_inventory_header_group(
    *,
    sequence: int,
    container_code: int,
) -> tuple[BDOFrame, list[BDOEvent], EventSpec, int]:
    item_offset = 34
    stride = 230
    count = 3
    base_length = 255
    message_length = base_length + (count - 1) * stride
    message = bytearray(message_length)
    message[:2] = message_length.to_bytes(2, "little")
    message[3:5] = (0x1424).to_bytes(2, "little")
    message[21:25] = CHARACTER_LOAD_CONTEXT
    message[33] = container_code
    flow_key = FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000)
    flow = Flow("10.0.0.1", 8889, "10.0.0.2", 50000)
    records: list[BDOEvent] = []
    for index in range(count):
        record_offset = item_offset + index * stride
        records.append(
            BDOEvent(
                event_type="inventory_snapshot",
                timestamp=float(sequence),
                flow=flow,
                item_id=7003 + index,
                quantity=1,
                opcode=0x1424,
                message_length=message_length,
                item_instance=f"header-instance-{sequence}-{index}",
                record_index=index + 1,
                record_count=count,
                record_offset=record_offset,
                extra={"stream_sequence": sequence},
            )
        )
    frame = BDOFrame(
        index=sequence,
        message=bytes(message),
        context=PacketContext(
            timestamp=float(sequence),
            flow=flow_key,
            stream_start=sequence,
        ),
        stream_sequence=sequence,
    )
    spec = EventSpec(
        label="INVENTORY_TRANSFER",
        opcode=0x1424,
        item_offset=item_offset,
        quantity_offset=item_offset + 4,
        min_message_length=base_length,
        source_context_offset=21,
        item_instance_offset=69,
        single_record_message_length=base_length,
    )
    return frame, records, spec, stride


def test_inventory_container_layout_is_discovered_from_august_wrapper_header():
    groups = [
        _synthetic_inventory_header_group(
            sequence=400 + code,
            container_code=code,
        )
        for code in (0x00, 0x0B)
    ]

    assert character_state_module._discover_inventory_tail_layout(groups) is None
    offset = character_state_module._discover_inventory_header_container_offset(
        groups
    )
    assert offset == 33

    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(groups[0][2],),
    )
    assembly = accumulator._inventory_summary(
        tuple(frame for frame, _, _, _ in groups),
        tuple(event for _, records, _, _ in groups for event in records),
        generations_observed=1,
    )
    summary = assembly.summary

    assert assembly.diagnostics.inferred_strides == (230,)
    assert summary.unclassified_records == 0
    assert summary.container(0x00).occupied_stacks == 3
    assert summary.container(0x0B).occupied_stacks == 3
    assert all(item.inventory_slot is None for item in summary.items)


def test_inventory_summary_selects_unique_geometry_from_same_opcode_layouts():
    groups = [
        _synthetic_inventory_tail_group(
            sequence=350 + code,
            stride=223,
            slot_relative=221,
            container_relative=222,
            container_code=code,
        )
        for code in (0x00, 0x0B)
    ]
    valid_spec = groups[0][2]
    invalid_last_wins_decoy = EventSpec(
        label="INVENTORY_TRANSFER",
        opcode=valid_spec.opcode,
        item_offset=33,
        quantity_offset=37,
        min_message_length=255,
        source_context_offset=27,
        item_instance_offset=68,
        single_record_message_length=255,
    )
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(valid_spec, invalid_last_wins_decoy),
    )

    assembly = accumulator._inventory_summary(
        tuple(frame for frame, _, _, _ in groups),
        tuple(event for _, records, _, _ in groups for event in records),
        generations_observed=1,
    )
    summary = assembly.summary

    assert assembly.diagnostics.inferred_strides == (223,)
    assert summary.unclassified_records == 0
    assert summary.container(0x00).occupied_stacks == 3
    assert summary.container(0x0B).occupied_stacks == 3


def test_known_currency_id_requires_its_observed_container_pairing():
    event = BDOEvent(
        event_type="inventory_snapshot",
        timestamp=1.0,
        flow=Flow("10.0.0.1", 8889, "10.0.0.2", 50000),
        item_id=6,
        quantity=1,
    )
    metadata = character_state_module._InventoryRecordMetadata(
        slot=5,
        container_code=0x00,
    )

    item = character_state_module._snapshot_item(event, "instance", metadata)

    assert item.currency_name is None
    assert not item.is_currency_balance
    assert item.container_name == "Main Inventory"


def _snapshot_record(
    *,
    timestamp: float,
    sequence: int,
    storage: bool,
    instance_byte: int,
    storage_id: int = 0x0020,
    item_id: int | None = None,
    quantity: int | None = None,
    include_instance: bool = True,
    flow_generation: int = 0,
) -> LootEvent:
    return LootEvent(
        label="INVENTORY_TO_STORAGE" if storage else "INVENTORY_TRANSFER",
        opcode=0x126D if storage else 0x194A,
        item_id=7003 + instance_byte if item_id is None else item_id,
        quantity=instance_byte if quantity is None else quantity,
        inventory_slot=None,
        source_context_candidate=(
            bytes.fromhex("20000000") if storage else CHARACTER_LOAD_CONTEXT
        ),
        item_instance=(
            bytes([instance_byte]) * 8 if not storage and include_instance else None
        ),
        storage_instance=(
            bytes([instance_byte]) * 8 if storage and include_instance else None
        ),
        message_length=257 if storage else 254,
        default_context="Storage" if storage else None,
        context=PacketContext(
            timestamp=timestamp,
            flow=FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000),
            stream_start=sequence,
            flow_generation=flow_generation,
        ),
        stream_sequence=sequence,
        record_offset=36 if storage else 31,
        storage_id=storage_id if storage else None,
        storage_operation="snapshot" if storage else None,
    )


def _storage_snapshot_spec() -> EventSpec:
    return EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
        source_context_offset=27,
        record_count_offset=16,
        storage_instance_offset=71,
        repeat_stride=222,
        single_record_message_length=257,
    )


def _empty_storage_frame(
    *,
    timestamp: float,
    sequence: int,
    storage_id: int = 0x0020,
    flow_generation: int = 0,
) -> BDOFrame:
    message = bytearray(35)
    message[:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x126D).to_bytes(2, "little")
    message[6] = 2
    message[27:31] = storage_id.to_bytes(4, "little")
    return BDOFrame(
        index=sequence,
        message=bytes(message),
        context=PacketContext(
            timestamp=timestamp,
            flow=FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000),
            stream_start=sequence,
            flow_generation=flow_generation,
        ),
        stream_sequence=sequence,
    )


def _inventory_snapshot_spec() -> EventSpec:
    return EventSpec(
        label="INVENTORY_TRANSFER",
        opcode=0x194A,
        item_offset=31,
        quantity_offset=35,
        min_message_length=254,
        source_context_offset=27,
        item_instance_offset=66,
        repeat_stride=223,
        single_record_message_length=254,
    )


def _empty_inventory_frame(*, timestamp: float, sequence: int) -> BDOFrame:
    spec = _inventory_snapshot_spec()
    message = bytearray(31)
    message[:2] = len(message).to_bytes(2, "little")
    message[3:5] = spec.opcode.to_bytes(2, "little")
    message[27:31] = CHARACTER_LOAD_CONTEXT
    return BDOFrame(
        index=sequence,
        message=bytes(message),
        context=PacketContext(
            timestamp=timestamp,
            flow=FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000),
            stream_start=sequence,
        ),
        stream_sequence=sequence,
    )


def test_empty_inventory_hydration_is_not_confused_with_no_observation():
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(_inventory_snapshot_spec(),),
    )
    accumulator.observe_frame(_empty_inventory_frame(timestamp=1.0, sequence=100))

    state = accumulator.snapshot()

    assert state.inventory.hydration_observed
    assert state.inventory.serialized_records == 0
    assert state.hydration_detected
    diagnostics = _inventory_diagnostics(state)
    assert diagnostics.group_counts == (0,)
    assert diagnostics.generations_observed == 1
    assert state.provenance.generation_selection == "latest_observed_inventory_hydration"
    assert "INVENTORY SNAPSHOT\n  NOT DETECTED" not in format_character_state(state)


def test_latest_empty_inventory_generation_clears_earlier_items():
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(_inventory_snapshot_spec(),),
    )
    accumulator.observe_record(
        _snapshot_record(
            timestamp=1.0,
            sequence=100,
            storage=False,
            instance_byte=1,
        ),
        b"",
    )
    accumulator.observe_record(
        _snapshot_record(
            timestamp=2.0,
            sequence=200,
            storage=True,
            instance_byte=2,
        ),
        b"",
    )
    accumulator.observe_frame(_empty_inventory_frame(timestamp=10.0, sequence=300))
    accumulator.observe_record(
        _snapshot_record(
            timestamp=11.0,
            sequence=400,
            storage=True,
            instance_byte=3,
        ),
        b"",
    )

    state = accumulator.snapshot()

    assert state.inventory.hydration_observed
    assert state.inventory.items == ()
    diagnostics = _inventory_diagnostics(state)
    assert diagnostics.raw_records == 0
    assert diagnostics.group_counts == (0,)
    assert diagnostics.generations_observed == 2
    heidel = state.storages.by_id(0x0020)
    assert heidel is not None
    assert [item.item_id for item in heidel.items] == [7006]
    assert state.diagnostics is not None
    assert state.diagnostics.storage.records_decoded == 1


_CHARACTER_STATE_FLOW = Flow("10.0.0.1", 8889, "10.0.0.2", 50000)


def _state_inventory_anchor(
    *,
    timestamp: float = 1.0,
    sequence: int = 100,
    flow: Flow = _CHARACTER_STATE_FLOW,
    flow_generation: int = 0,
) -> BDOEvent:
    event = BDOEvent(
        event_type="inventory_snapshot",
        timestamp=timestamp,
        flow=flow,
        item_id=7003,
        quantity=1,
        opcode=0x194A,
        message_length=254,
        item_instance=f"inventory-anchor-{flow_generation}",
        record_index=1,
        record_count=1,
        record_offset=31,
        extra={"stream_sequence": sequence},
    )
    return replace(event, _flow_generation=flow_generation)


def _state_storage_event(
    *,
    timestamp: float,
    sequence: int,
    storage_id: int,
    event_type: str,
    opcode: int = 0x126D,
    flow: Flow = _CHARACTER_STATE_FLOW,
    flow_generation: int = 0,
) -> BDOEvent:
    location = character_state_module.STORAGE_LOCATIONS.get(storage_id)
    event = BDOEvent(
        event_type=event_type,
        timestamp=timestamp,
        flow=flow,
        item_id=7003 + storage_id,
        quantity=1,
        opcode=opcode,
        message_length=257,
        storage_instance=f"storage-{opcode}-{storage_id}-{sequence}",
        storage_id=storage_id,
        storage_name=location.name if location is not None else None,
        storage_name_confidence=(
            location.confidence if location is not None else None
        ),
        record_index=1,
        record_count=1,
        record_offset=36,
        extra={"stream_sequence": sequence},
    )
    return replace(event, _flow_generation=flow_generation)


@pytest.mark.parametrize(
    ("first_type", "first_count", "second_type", "second_count"),
    [
        ("storage_record", 4, "storage_snapshot", 8),
        ("storage_snapshot", 8, "storage_record", 4),
    ],
    ids=("neutral-4-then-proven-8", "proven-8-then-neutral-4"),
)
def test_character_state_reconciles_one_hydration_sweep_split_across_bursts(
    first_type: str,
    first_count: int,
    second_type: str,
    second_count: int,
) -> None:
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(_storage_snapshot_spec(),),
    )
    accumulator.observe_event(_state_inventory_anchor())
    storage_ids = tuple(character_state_module.STORAGE_LOCATIONS)[:12]

    offset = 0
    for event_type, count, start_time in (
        (first_type, first_count, 1.10),
        (second_type, second_count, 1.80),
    ):
        for index in range(count):
            accumulator.observe_event(
                _state_storage_event(
                    timestamp=start_time + index * 0.01,
                    sequence=200 + (offset + index) * 300,
                    storage_id=storage_ids[offset + index],
                    event_type=event_type,
                )
            )
        offset += count

    state = accumulator.snapshot()

    assert state.diagnostics is not None
    assert state.diagnostics.storage.records_decoded == 12
    assert state.storages.registered_count == 12
    assert {storage.storage_id for storage in state.storages} == set(storage_ids)
    assert any("split across timing bursts" in warning for warning in state.warnings)


def test_split_hydration_reconciliation_stops_at_a_live_mutation_boundary() -> None:
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(_storage_snapshot_spec(),),
    )
    accumulator.observe_event(_state_inventory_anchor())
    storage_ids = tuple(character_state_module.STORAGE_LOCATIONS)[:13]
    for index, storage_id in enumerate(storage_ids[:4]):
        accumulator.observe_event(
            _state_storage_event(
                timestamp=1.10 + index * 0.01,
                sequence=200 + index * 300,
                storage_id=storage_id,
                event_type="storage_record",
            )
        )
    accumulator.observe_event(
        _state_storage_event(
            timestamp=1.50,
            sequence=1_500,
            storage_id=storage_ids[4],
            event_type="storage_delta",
        )
    )
    for index, storage_id in enumerate(storage_ids[5:]):
        accumulator.observe_event(
            _state_storage_event(
                timestamp=1.80 + index * 0.01,
                sequence=1_800 + index * 300,
                storage_id=storage_id,
                event_type="storage_snapshot",
            )
        )

    state = accumulator.snapshot()

    assert state.diagnostics is not None
    assert state.diagnostics.storage.records_decoded == 8
    assert state.storages.registered_count == 8
    assert all(state.storages.by_id(storage_id) is None for storage_id in storage_ids[:4])
    assert state.diagnostics.snapshot_records_retained == 13
    assert not any("split across timing bursts" in warning for warning in state.warnings)


def test_split_hydration_reconciliation_does_not_cross_opcode_families() -> None:
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(_storage_snapshot_spec(),),
    )
    accumulator.observe_event(_state_inventory_anchor())
    storage_ids = tuple(character_state_module.STORAGE_LOCATIONS)[:12]
    for index, storage_id in enumerate(storage_ids[:4]):
        accumulator.observe_event(
            _state_storage_event(
                timestamp=1.10 + index * 0.01,
                sequence=200 + index * 300,
                storage_id=storage_id,
                event_type="storage_record",
                opcode=0x126D,
            )
        )
    for index, storage_id in enumerate(storage_ids[4:]):
        accumulator.observe_event(
            _state_storage_event(
                timestamp=1.80 + index * 0.01,
                sequence=1_500 + index * 300,
                storage_id=storage_id,
                event_type="storage_snapshot",
                opcode=0x1C51,
            )
        )

    state = accumulator.snapshot()

    assert state.diagnostics is not None
    assert state.diagnostics.storage.records_decoded == 8
    assert all(state.storages.by_id(storage_id) is None for storage_id in storage_ids[:4])


@pytest.mark.parametrize("isolation", ["flow", "generation"])
def test_split_hydration_reconciliation_isolates_connection_identity(
    isolation: str,
) -> None:
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(_storage_snapshot_spec(),),
    )
    selected_generation = 2 if isolation == "generation" else 0
    accumulator.observe_event(
        _state_inventory_anchor(flow_generation=selected_generation)
    )
    storage_ids = tuple(character_state_module.STORAGE_LOCATIONS)[:12]
    neutral_flow = (
        Flow("10.0.0.3", 8889, "10.0.0.4", 50001)
        if isolation == "flow"
        else _CHARACTER_STATE_FLOW
    )
    neutral_generation = 1 if isolation == "generation" else 0
    for index, storage_id in enumerate(storage_ids[:4]):
        accumulator.observe_event(
            _state_storage_event(
                timestamp=1.10 + index * 0.01,
                sequence=200 + index * 300,
                storage_id=storage_id,
                event_type="storage_record",
                flow=neutral_flow,
                flow_generation=neutral_generation,
            )
        )
    for index, storage_id in enumerate(storage_ids[4:]):
        accumulator.observe_event(
            _state_storage_event(
                timestamp=1.80 + index * 0.01,
                sequence=1_500 + index * 300,
                storage_id=storage_id,
                event_type="storage_snapshot",
                flow_generation=selected_generation,
            )
        )

    state = accumulator.snapshot()

    assert state.diagnostics is not None
    assert state.diagnostics.storage.records_decoded == 8
    assert all(state.storages.by_id(storage_id) is None for storage_id in storage_ids[:4])


def test_subthreshold_neutral_storage_remains_unclassified_in_character_state() -> None:
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(_storage_snapshot_spec(),),
    )
    accumulator.observe_event(_state_inventory_anchor())
    storage_ids = tuple(character_state_module.STORAGE_LOCATIONS)[:4]
    for index, storage_id in enumerate(storage_ids):
        accumulator.observe_event(
            _state_storage_event(
                timestamp=1.10 + index * 0.01,
                sequence=200 + index * 300,
                storage_id=storage_id,
                event_type="storage_record",
            )
        )

    state = accumulator.snapshot()

    assert state.diagnostics is not None
    assert state.diagnostics.storage.records_decoded == 0
    assert state.storages.registered_count == 0
    assert all(state.storages.by_id(storage_id) is None for storage_id in storage_ids)


@pytest.mark.parametrize("repeat_stride", [222, None])
def test_character_load_uses_empty_envelopes_for_sparse_storage_hydration(
    repeat_stride: int | None,
):
    spec = replace(
        _storage_snapshot_spec(),
        repeat_stride=repeat_stride,
    )
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(spec,),
    )
    accumulator.observe_record(
        _snapshot_record(
            timestamp=1.0,
            sequence=100,
            storage=False,
            instance_byte=1,
        ),
        b"",
    )

    storage_ids = tuple(character_state_module.STORAGE_LOCATIONS)[:8]
    flow = Flow("10.0.0.1", 8889, "10.0.0.2", 50000)
    for index, storage_id in enumerate(storage_ids[:3]):
        accumulator.observe_event(
            BDOEvent(
                event_type="storage_record",
                timestamp=1.20 + index * 0.01,
                flow=flow,
                item_id=7003 + index,
                quantity=1,
                opcode=spec.opcode,
                message_length=spec.single_record_message_length,
                storage_instance=f"sparse-{index}",
                storage_id=storage_id,
                storage_name=character_state_module.STORAGE_LOCATIONS[storage_id].name,
                storage_name_confidence="observed",
                record_index=1,
                record_count=1,
                record_offset=spec.item_offset,
                extra={"stream_sequence": 200 + index * 100},
            )
        )
    for index, storage_id in enumerate(storage_ids[3:]):
        accumulator.observe_frame(
            _empty_storage_frame(
                timestamp=1.25 + index * 0.01,
                sequence=500 + index * 100,
                storage_id=storage_id,
            )
        )

    state = accumulator.snapshot(
        decoder_health=DecoderHealth(
            storage_status="compatible",
            storage_messages_observed=8,
            storage_messages_decoded=3,
            storage_records_decoded=3,
        )
    )

    assert state.diagnostics is not None
    assert state.diagnostics.storage.records_decoded == 3
    assert state.storages.registered_count == 8
    assert state.storages.nonempty_count == 3
    assert state.storages.empty_count == 5
    assert state.decoder_health.storage_status == "compatible"
    assert any("dedicated character-load boundary" in warning for warning in state.warnings)
    assert state.to_dict()["decoder_health"]["storage_status"] == "compatible"


def test_classified_nonempty_snapshot_keeps_leading_empty_envelopes_without_stride():
    """The inventory anchor covers empty towns outside the nonempty event window."""
    spec = replace(_storage_snapshot_spec(), repeat_stride=None)
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(spec,),
    )
    accumulator.observe_record(
        _snapshot_record(
            timestamp=1.0,
            sequence=100,
            storage=False,
            instance_byte=1,
        ),
        b"",
    )

    storage_ids = tuple(character_state_module.STORAGE_LOCATIONS)[:10]
    for index, storage_id in enumerate(storage_ids[:2]):
        accumulator.observe_frame(
            _empty_storage_frame(
                timestamp=1.10 + index * 0.01,
                sequence=200 + index * 100,
                storage_id=storage_id,
            )
        )

    flow = Flow("10.0.0.1", 8889, "10.0.0.2", 50000)
    for index, storage_id in enumerate(storage_ids[2:]):
        accumulator.observe_event(
            BDOEvent(
                event_type="storage_snapshot",
                timestamp=1.20 + index * 0.01,
                flow=flow,
                item_id=7003 + index,
                quantity=1,
                opcode=spec.opcode,
                message_length=spec.single_record_message_length,
                storage_instance=f"classified-{index}",
                storage_id=storage_id,
                storage_name=(
                    character_state_module.STORAGE_LOCATIONS[storage_id].name
                ),
                storage_name_confidence="observed",
                record_index=1,
                record_count=1,
                record_offset=spec.item_offset,
                extra={"stream_sequence": 500 + index * 100},
            )
        )

    state = accumulator.snapshot(
        decoder_health=DecoderHealth(
            storage_status="compatible",
            storage_messages_observed=8,
            storage_messages_decoded=8,
            storage_records_decoded=8,
        )
    )

    assert state.storages.registered_count == 10
    assert state.storages.nonempty_count == 8
    assert state.storages.empty_count == 2


def test_empty_cohort_cannot_override_observed_multi_record_geometry():
    spec = _storage_snapshot_spec()
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(spec,),
    )
    accumulator.observe_record(
        _snapshot_record(
            timestamp=1.0,
            sequence=100,
            storage=False,
            instance_byte=1,
        ),
        b"",
    )

    storage_ids = tuple(character_state_module.STORAGE_LOCATIONS)[:10]
    flow = Flow("10.0.0.1", 8889, "10.0.0.2", 50000)
    proven_stride = 222
    multi_length = spec.single_record_message_length + proven_stride
    for index in range(2):
        accumulator.observe_event(
            BDOEvent(
                event_type="storage_snapshot",
                timestamp=1.20,
                flow=flow,
                item_id=7003 + index,
                quantity=1,
                opcode=spec.opcode,
                message_length=multi_length,
                storage_instance=f"multi-{index}",
                storage_id=storage_ids[0],
                storage_name=(
                    character_state_module.STORAGE_LOCATIONS[storage_ids[0]].name
                ),
                storage_name_confidence="observed",
                record_index=index + 1,
                record_count=2,
                record_offset=spec.item_offset + index * proven_stride,
                extra={"stream_sequence": 200},
            )
        )

    # A broad, internally consistent cohort at the wrong length used to win
    # over the exact stride proved by the decoded two-record wrapper above.
    for index, storage_id in enumerate(storage_ids[1:9]):
        frame = _empty_storage_frame(
            timestamp=1.21 + index * 0.01,
            sequence=300 + index * 100,
            storage_id=storage_id,
        )
        wrong_length = bytearray(frame.message[:-1])
        wrong_length[:2] = len(wrong_length).to_bytes(2, "little")
        accumulator.observe_frame(replace(frame, message=bytes(wrong_length)))

    accumulator.observe_frame(
        _empty_storage_frame(
            timestamp=1.30,
            sequence=1_200,
            storage_id=storage_ids[9],
        )
    )

    state = accumulator.snapshot(
        decoder_health=DecoderHealth(
            storage_status="compatible",
            storage_messages_observed=2,
            storage_messages_decoded=2,
            storage_records_decoded=2,
        )
    )

    assert state.storages.registered_count == 2
    assert state.storages.nonempty_count == 1
    assert state.storages.empty_count == 1
    assert state.storages.by_id(storage_ids[9]).current_empty
    assert all(
        state.storages.by_id(storage_id) is None for storage_id in storage_ids[1:9]
    )


def test_character_state_does_not_merge_reused_four_tuple_generations():
    accumulator = _CharacterStateAccumulator(profile_source="test", specs=())
    for generation, timestamp, instance_byte in ((0, 1.0, 1), (1, 1.01, 2)):
        accumulator.observe_record(
            _snapshot_record(
                timestamp=timestamp,
                sequence=100,
                storage=False,
                instance_byte=instance_byte,
                flow_generation=generation,
            ),
            b"",
        )
    accumulator.observe_record(
        _snapshot_record(
            timestamp=1.10,
            sequence=200,
            storage=True,
            storage_id=0x0020,
            instance_byte=3,
            flow_generation=0,
        ),
        b"",
    )
    accumulator.observe_record(
        _snapshot_record(
            timestamp=1.11,
            sequence=200,
            storage=True,
            storage_id=0x0005,
            instance_byte=4,
            flow_generation=1,
        ),
        b"",
    )

    state = accumulator.snapshot()

    assert state.diagnostics is not None
    assert state.diagnostics.inventory.generations_observed == 2
    assert state.diagnostics.inventory.raw_records == 1
    assert [item.item_id for item in state.inventory.items] == [7005]
    assert state.storages.by_id(0x0020) is None
    assert state.storages.by_id(0x0005) is not None


def test_sparse_empty_envelopes_do_not_cross_reused_flow_generations():
    spec = replace(_storage_snapshot_spec(), repeat_stride=None)
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(spec,),
    )
    accumulator.observe_record(
        _snapshot_record(
            timestamp=1.0,
            sequence=100,
            storage=False,
            instance_byte=1,
            flow_generation=2,
        ),
        b"",
    )

    storage_ids = tuple(character_state_module.STORAGE_LOCATIONS)[:8]
    flow = Flow("10.0.0.1", 8889, "10.0.0.2", 50000)
    for index, storage_id in enumerate(storage_ids[:3]):
        accumulator.observe_event(
            BDOEvent(
                event_type="storage_record",
                timestamp=1.20 + index * 0.01,
                flow=flow,
                item_id=7003 + index,
                quantity=1,
                opcode=spec.opcode,
                message_length=spec.single_record_message_length,
                storage_instance=f"generation-two-{index}",
                storage_id=storage_id,
                record_index=1,
                record_count=1,
                record_offset=spec.item_offset,
                extra={"stream_sequence": 200 + index * 100},
                _flow_generation=2,
            )
        )
    for index, storage_id in enumerate(storage_ids[3:]):
        accumulator.observe_frame(
            _empty_storage_frame(
                timestamp=1.25 + index * 0.01,
                sequence=500 + index * 100,
                storage_id=storage_id,
                flow_generation=1,
            )
        )

    state = accumulator.snapshot()

    assert state.diagnostics is not None
    assert state.diagnostics.storage.records_decoded == 0
    assert state.storages.registered_count == 0


def test_all_empty_character_storage_preserves_an_unregistered_numeric_id():
    spec = replace(_storage_snapshot_spec(), repeat_stride=None)
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(spec,),
    )
    accumulator.observe_record(
        _snapshot_record(
            timestamp=1.0,
            sequence=100,
            storage=False,
            instance_byte=1,
        ),
        b"",
    )
    unknown_storage_id = 0x12345678
    storage_ids = (
        *tuple(character_state_module.STORAGE_LOCATIONS)[:7],
        unknown_storage_id,
    )
    for index, storage_id in enumerate(storage_ids):
        accumulator.observe_frame(
            _empty_storage_frame(
                timestamp=1.20 + index * 0.01,
                sequence=200 + index * 100,
                storage_id=storage_id,
            )
        )

    state = accumulator.snapshot()

    assert state.diagnostics is not None
    assert state.diagnostics.storage.records_decoded == 0
    assert state.storages.empty_count == 8
    assert state.storages.by_id(unknown_storage_id) is not None
    assert state.storages.by_id(unknown_storage_id).name is None
    assert state.coverage.unregistered_storage_ids_observed == (unknown_storage_id,)
    assert state.decoder_health.storage_status == "incompatible"
    assert state.decoder_health.storage_destination_failures == 1
    assert not any("opcode was not observed" in warning for warning in state.warnings)
    assert any("numeric identities were preserved" in warning for warning in state.warnings)


def test_unknown_empty_envelope_adds_to_decoded_destination_failure_count():
    spec = _storage_snapshot_spec()
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(spec,),
    )
    accumulator.observe_record(
        _snapshot_record(
            timestamp=1.0,
            sequence=100,
            storage=False,
            instance_byte=1,
        ),
        b"",
    )

    decoded_unknown_id = 0x12345678
    empty_unknown_id = 0x23456789
    flow = Flow("10.0.0.1", 8889, "10.0.0.2", 50000)
    accumulator.observe_event(
        BDOEvent(
            event_type="storage_record",
            timestamp=1.20,
            flow=flow,
            item_id=7003,
            quantity=1,
            opcode=spec.opcode,
            message_length=spec.single_record_message_length,
            storage_instance="decoded-unknown",
            storage_id=decoded_unknown_id,
            record_index=1,
            record_count=1,
            record_offset=spec.item_offset,
            extra={"stream_sequence": 200},
        )
    )
    empty_ids = (
        *tuple(character_state_module.STORAGE_LOCATIONS)[:6],
        empty_unknown_id,
    )
    for index, storage_id in enumerate(empty_ids):
        accumulator.observe_frame(
            _empty_storage_frame(
                timestamp=1.21 + index * 0.01,
                sequence=300 + index * 100,
                storage_id=storage_id,
            )
        )

    state = accumulator.snapshot(
        decoder_health=DecoderHealth(
            storage_status="incompatible",
            storage_messages_observed=1,
            storage_messages_decoded=1,
            storage_records_decoded=1,
            storage_destination_failures=1,
        )
    )

    assert state.diagnostics is not None
    assert state.diagnostics.storage.records_decoded == 1
    assert state.storages.registered_count == 6
    assert state.coverage.unregistered_storage_ids_observed == (
        decoded_unknown_id,
        empty_unknown_id,
    )
    assert state.decoder_health.storage_destination_failures == 2


def test_repeated_inventory_observation_keeps_raw_and_state_counts_distinct():
    accumulator = _CharacterStateAccumulator(profile_source="test", specs=())
    for timestamp, sequence in ((1.0, 100), (1.1, 200)):
        accumulator.observe_record(
            _snapshot_record(
                timestamp=timestamp,
                sequence=sequence,
                storage=False,
                instance_byte=1,
            ),
            b"",
        )

    state = accumulator.snapshot()

    inventory_diagnostics = _inventory_diagnostics(state)
    assert (
        inventory_diagnostics.raw_records,
        inventory_diagnostics.duplicate_records,
    ) == (2, 1)
    assert state.inventory.serialized_records == 1
    output = format_character_state(state)
    assert (
        "1 serialized records: 1 occupied item stacks + 0 currency balances" in output
    )
    assert "2 serialized records:" not in output


def test_missing_instance_records_are_excluded_from_distinct_stack_state():
    accumulator = _CharacterStateAccumulator(profile_source="test", specs=())
    for storage, base_sequence in ((False, 100), (True, 300)):
        for index in range(2):
            accumulator.observe_record(
                _snapshot_record(
                    timestamp=1.0 + index / 10,
                    sequence=base_sequence + index * 100,
                    storage=storage,
                    instance_byte=1,
                    item_id=7003,
                    quantity=5,
                    include_instance=False,
                ),
                b"",
            )

    state = accumulator.snapshot()
    heidel = state.storages.by_id(0x0020)
    inventory_diagnostics = _inventory_diagnostics(state)

    assert state.inventory.items == ()
    assert inventory_diagnostics.raw_records == 2
    assert heidel is not None
    heidel_diagnostics = _storage_diagnostics(state, heidel.storage_id)
    assert heidel.items == ()
    assert (
        heidel_diagnostics.missing_instance_records,
        heidel_diagnostics.selected_missing_instance_records,
    ) == (2, 2)
    assert heidel.current_identity_complete is False
    assert heidel.current_empty is False
    assert not state.identity_complete

    coverage = state.coverage
    assert (
        coverage.inventory_records_missing_instance,
        coverage.storage_records_missing_instance,
        coverage.selected_storage_records_missing_instance,
    ) == (2, 2, 2)
    assert coverage.storage_locations_with_incomplete_current_identity == 1
    output = format_character_state(state)
    assert output.count("identity-unresolved records excluded: 2") == 2
    assert "1 identity-incomplete" in output


def test_unresolved_storage_destination_still_contributes_to_identity_coverage():
    accumulator = _CharacterStateAccumulator(profile_source="test", specs=())
    accumulator.observe_event(
        BDOEvent(
            event_type="storage_snapshot",
            timestamp=1.0,
            flow=Flow("10.0.0.1", 8889, "10.0.0.2", 50000),
            item_id=7003,
            quantity=5,
            opcode=0x126D,
            message_length=257,
            storage_instance=None,
            storage_id=None,
            record_index=1,
            record_count=1,
            record_offset=36,
            extra={"stream_sequence": 100},
        )
    )

    state = accumulator.snapshot()

    assert state.storages == ()
    assert state.coverage.storage_records_missing_instance == 1
    assert state.coverage.selected_storage_records_missing_instance == 0
    assert not state.identity_complete
    assert state.diagnostics is not None
    assert state.diagnostics.storage.records_without_destination == 1


def test_mixed_storage_identity_exposes_only_the_authoritative_stack():
    accumulator = _CharacterStateAccumulator(profile_source="test", specs=())
    for include_instance, instance_byte in ((True, 1), (False, 2)):
        accumulator.observe_record(
            _snapshot_record(
                timestamp=1.0,
                sequence=100,
                storage=True,
                instance_byte=instance_byte,
                item_id=7003,
                quantity=5,
                include_instance=include_instance,
            ),
            b"",
        )

    state = accumulator.snapshot()
    heidel = state.storages.by_id(0x0020)

    assert heidel is not None
    assert len(heidel.items) == 1
    heidel_diagnostics = _storage_diagnostics(state, heidel.storage_id)
    assert heidel_diagnostics.selected_missing_instance_records == 1
    assert heidel.quantity_for(7003) == 5


def test_item_state_profile_geometry_requires_identity_and_wrapper_authority():
    missing_inventory_identity = EventSpec(
        label="INVENTORY_TRANSFER",
        opcode=0x194A,
        item_offset=31,
        quantity_offset=35,
        min_message_length=254,
    )
    missing_storage_identity = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
    )

    with pytest.raises(
        character_state_module.ProfileError,
        match="require calibrated identity and wrapper authority",
    ):
        character_state_module._validate_item_state_identity_specs(
            (missing_inventory_identity, missing_storage_identity)
        )

    character_state_module._validate_item_state_identity_specs(
        (
            EventSpec(
                label="INVENTORY_TRANSFER",
                opcode=0x194A,
                item_offset=31,
                quantity_offset=35,
                min_message_length=254,
                item_instance_offset=66,
                source_context_offset=27,
            ),
            EventSpec(
                label="INVENTORY_TO_STORAGE",
                opcode=0x126D,
                item_offset=36,
                quantity_offset=40,
                min_message_length=257,
                storage_instance_offset=71,
                source_context_offset=27,
                record_count_offset=16,
            ),
        )
    )


def test_item_state_record_limit_fails_closed_without_partial_snapshot():
    limits = ItemStateCaptureLimits(
        max_relevant_frames=10,
        max_snapshot_records=1,
        max_relevant_bytes=1_000,
    )
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(),
        capture_limits=limits,
    )
    accumulator.observe_record(
        _snapshot_record(
            timestamp=1.0,
            sequence=100,
            storage=False,
            instance_byte=1,
        ),
        b"",
    )

    within_limit = accumulator.snapshot()
    assert within_limit.diagnostics is not None
    assert within_limit.diagnostics.snapshot_records_retained == 1
    assert within_limit.diagnostics.capture_limits.max_snapshot_records == 1

    with pytest.raises(ItemStateCaptureLimitError) as raised:
        accumulator.observe_record(
            _snapshot_record(
                timestamp=2.0,
                sequence=200,
                storage=False,
                instance_byte=2,
            ),
            b"",
        )
    error = raised.value
    assert error.limit_name == "max_snapshot_records"
    assert error.limit == 1
    assert error.attempted == 2
    with pytest.raises(ItemStateCaptureLimitError) as snapshot_error:
        accumulator.snapshot()
    assert snapshot_error.value is error


def test_item_state_frame_and_byte_limits_bound_retained_frame_memory():
    spec = _storage_snapshot_spec()
    frame = _empty_storage_frame(timestamp=1.0, sequence=100)
    frame_limited = _CharacterStateAccumulator(
        profile_source="test",
        specs=(spec,),
        capture_limits=ItemStateCaptureLimits(
            max_relevant_frames=1,
            max_snapshot_records=10,
            max_relevant_bytes=1_000,
        ),
    )
    frame_limited.observe_frame(frame)
    with pytest.raises(ItemStateCaptureLimitError, match="max_relevant_frames"):
        frame_limited.observe_frame(_empty_storage_frame(timestamp=2.0, sequence=200))
    assert len(frame_limited._frames) == 1
    assert len(frame_limited._seen_frames) == 1

    byte_limited = _CharacterStateAccumulator(
        profile_source="test",
        specs=(spec,),
        capture_limits=ItemStateCaptureLimits(
            max_relevant_frames=10,
            max_snapshot_records=10,
            max_relevant_bytes=len(frame.message) - 1,
        ),
    )
    with pytest.raises(ItemStateCaptureLimitError, match="max_relevant_bytes"):
        byte_limited.observe_frame(frame)
    assert byte_limited._frames == []
    assert byte_limited._seen_frames == set()


def test_storage_item_then_empty_selects_atomic_latest_empty_state():
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(_storage_snapshot_spec(),),
    )
    accumulator.observe_record(
        _snapshot_record(
            timestamp=1.0,
            sequence=100,
            storage=True,
            instance_byte=1,
            quantity=5,
        ),
        b"",
    )
    accumulator.observe_frame(_empty_storage_frame(timestamp=2.0, sequence=200))

    state = accumulator.snapshot()
    heidel = state.storages.by_id(0x0020)

    assert heidel is not None
    assert heidel.items == ()
    assert heidel.occupied_stacks == 0
    assert heidel.current_state_observed
    assert heidel.current_empty is True
    heidel_diagnostics = _storage_diagnostics(state, heidel.storage_id)
    assert (
        heidel_diagnostics.empty_envelope_seen,
        heidel_diagnostics.raw_records,
        heidel_diagnostics.selected_records,
        heidel_diagnostics.superseded_records,
        heidel_diagnostics.selected_sweep,
    ) == (True, 1, 0, 1, 2)


def test_storage_empty_then_item_selects_latest_nonempty_state():
    accumulator = _CharacterStateAccumulator(
        profile_source="test",
        specs=(_storage_snapshot_spec(),),
    )
    accumulator.observe_frame(_empty_storage_frame(timestamp=1.0, sequence=100))
    accumulator.observe_record(
        _snapshot_record(
            timestamp=2.0,
            sequence=200,
            storage=True,
            instance_byte=1,
            quantity=9,
        ),
        b"",
    )

    state = accumulator.snapshot()
    heidel = state.storages.by_id(0x0020)

    assert heidel is not None
    assert [item.quantity for item in heidel.items] == [9]
    assert heidel.occupied_stacks == 1
    assert heidel.current_state_observed
    assert heidel.current_empty is False
    heidel_diagnostics = _storage_diagnostics(state, heidel.storage_id)
    assert heidel_diagnostics.empty_envelope_seen


def test_repeated_storage_sweep_replaces_items_but_preserves_diagnostics():
    accumulator = _CharacterStateAccumulator(profile_source="test", specs=())
    observations = (
        _snapshot_record(
            timestamp=1.0,
            sequence=100,
            storage=True,
            storage_id=0x0020,
            instance_byte=1,
            quantity=5,
        ),
        _snapshot_record(
            timestamp=2.0,
            sequence=200,
            storage=True,
            storage_id=0x0005,
            instance_byte=2,
            quantity=6,
        ),
        _snapshot_record(
            timestamp=3.0,
            sequence=300,
            storage=True,
            storage_id=0x0020,
            instance_byte=1,
            quantity=9,
        ),
        _snapshot_record(
            timestamp=4.0,
            sequence=400,
            storage=True,
            storage_id=0x0005,
            instance_byte=2,
            quantity=10,
        ),
    )
    for record in observations:
        accumulator.observe_record(record, b"")

    state = accumulator.snapshot()
    heidel = state.storages.by_id(0x0020)
    velia = state.storages.by_id(0x0005)

    assert heidel is not None and velia is not None
    assert [item.quantity for item in heidel.items] == [9]
    assert [item.quantity for item in velia.items] == [10]
    assert heidel.items[0].observed_at == 3.0
    assert velia.items[0].observed_at == 4.0
    assert state.storages.occupied_stacks == 2
    assert state.diagnostics is not None
    assert state.diagnostics.storage.records_decoded == 4
    assert state.diagnostics.storage.sweeps_observed == 2
    heidel_diagnostics = _storage_diagnostics(state, heidel.storage_id)
    assert (
        heidel_diagnostics.raw_records,
        heidel_diagnostics.duplicate_records,
        heidel_diagnostics.groups,
        heidel_diagnostics.selected_records,
        heidel_diagnostics.superseded_records,
        heidel_diagnostics.selected_groups,
        heidel_diagnostics.superseded_groups,
        heidel_diagnostics.sweeps_observed,
        heidel_diagnostics.selected_sweep,
    ) == (2, 1, 2, 1, 1, 1, 1, 2, 2)


def test_same_destination_after_chunk_gap_replaces_removed_instances():
    accumulator = _CharacterStateAccumulator(profile_source="test", specs=())
    observations = (
        _snapshot_record(
            timestamp=1.0,
            sequence=100,
            storage=True,
            instance_byte=1,
            quantity=5,
        ),
        _snapshot_record(
            timestamp=1.0,
            sequence=100,
            storage=True,
            instance_byte=2,
            quantity=6,
        ),
        _snapshot_record(
            timestamp=3.5,
            sequence=300,
            storage=True,
            instance_byte=1,
            quantity=9,
        ),
    )
    for record in observations:
        accumulator.observe_record(record, b"")

    state = accumulator.snapshot()
    heidel = state.storages.by_id(0x0020)

    assert heidel is not None
    assert [(item.item_id, item.quantity) for item in heidel.items] == [(7004, 9)]
    heidel_diagnostics = _storage_diagnostics(state, heidel.storage_id)
    assert heidel_diagnostics.raw_records == 3
    assert heidel_diagnostics.groups == 2
    assert heidel_diagnostics.selected_records == 1
    assert heidel_diagnostics.superseded_records == 2
    assert heidel_diagnostics.duplicate_records == 1
    assert heidel_diagnostics.sweeps_observed == 2
    assert state.diagnostics is not None
    assert state.diagnostics.storage.sweeps_observed == 2


def test_partial_later_storage_sweep_excludes_earlier_only_items():
    accumulator = _CharacterStateAccumulator(profile_source="test", specs=())
    observations = (
        _snapshot_record(
            timestamp=1.0,
            sequence=100,
            storage=True,
            storage_id=0x0020,
            instance_byte=1,
            quantity=5,
        ),
        _snapshot_record(
            timestamp=2.0,
            sequence=200,
            storage=True,
            storage_id=0x0005,
            instance_byte=2,
            quantity=6,
        ),
        _snapshot_record(
            timestamp=3.0,
            sequence=300,
            storage=True,
            storage_id=0x0020,
            instance_byte=1,
            quantity=9,
        ),
    )
    for record in observations:
        accumulator.observe_record(record, b"")

    state = accumulator.snapshot()
    heidel = state.storages.by_id(0x0020)
    velia = state.storages.by_id(0x0005)

    assert heidel is not None and velia is not None
    assert [item.quantity for item in heidel.items] == [9]
    assert heidel.current_state_observed
    assert _storage_diagnostics(state, heidel.storage_id).selected_sweep == 2
    assert velia.items == ()
    assert velia.occupied_stacks == 0
    assert not velia.current_state_observed
    assert velia.current_empty is None
    assert velia.current_identity_complete is None
    velia_diagnostics = _storage_diagnostics(state, velia.storage_id)
    assert velia_diagnostics.selected_sweep is None
    assert state.storages.occupied_stacks == 1
    assert state.storages.selected_count == 1
    assert state.storages.total_quantity(7005) == 0
    assert len(state.storages) == 2
    assert state.coverage.storage_locations_not_selected == 1
    assert any("selected sweep may be partial" in warning for warning in state.warnings)
    output = format_character_state(state)
    assert "Velia: current state unavailable" in output


def test_multiple_character_loads_report_only_the_latest_generation():
    accumulator = _CharacterStateAccumulator(profile_source="test", specs=())
    for record in (
        _snapshot_record(timestamp=1.0, sequence=100, storage=False, instance_byte=1),
        _snapshot_record(timestamp=2.0, sequence=200, storage=True, instance_byte=2),
        _snapshot_record(timestamp=10.0, sequence=300, storage=False, instance_byte=3),
        _snapshot_record(timestamp=11.0, sequence=400, storage=True, instance_byte=4),
    ):
        accumulator.observe_record(record, b"")

    state = accumulator.snapshot()

    assert state.diagnostics is not None
    assert state.diagnostics.inventory.generations_observed == 2
    assert [item.item_id for item in state.inventory.items] == [7006]
    assert state.diagnostics.storage.records_decoded == 1
    heidel = state.storages.by_id(0x0020)
    assert heidel is not None
    assert [item.item_id for item in heidel.items] == [7007]
    assert any("only the latest generation" in warning for warning in state.warnings)

    output = format_character_state(state)
    assert "1/34 known destinations observed" in output
    assert "1 non-empty, 0 explicitly empty, 33 not observed" in output
    assert "known destinations not observed:" in output
    missing_line = next(
        line
        for line in output.splitlines()
        if "known destinations not observed:" in line
    )
    assert "Heidel" not in missing_line


def test_storage_only_capture_discloses_that_no_generation_boundary_exists():
    accumulator = _CharacterStateAccumulator(profile_source="test", specs=())
    for record in (
        _snapshot_record(timestamp=2.0, sequence=200, storage=True, instance_byte=2),
        _snapshot_record(timestamp=11.0, sequence=400, storage=True, instance_byte=4),
    ):
        accumulator.observe_record(record, b"")

    state = accumulator.snapshot()

    assert state.diagnostics is not None
    assert state.diagnostics.inventory.generations_observed == 0
    assert state.diagnostics.storage.records_decoded == 2
    assert (
        state.provenance.generation_selection
        == "all_observed_storage_no_inventory_boundary"
    )
    assert any("may span multiple loads" in warning for warning in state.warnings)


@pytest.fixture
def character_load_live_fakes(monkeypatch):
    parser_packets = []

    class FakeSniffer:
        instances = []

        def __init__(self, *, prn, started_callback=None, **kwargs):
            self.prn = prn
            self.started_callback = started_callback
            self.kwargs = kwargs
            self.running = False
            self.exception = None
            self.stop_calls = 0
            self.__class__.instances.append(self)

        def start(self):
            self.running = True
            if self.started_callback is not None:
                self.started_callback()

        def stop(self):
            self.stop_calls += 1
            self.running = False

        def emit(self, packet):
            self.prn(packet)

    monkeypatch.setattr(
        capture_runtime,
        "import_scapy",
        lambda: (object(), object(), None, None, None),
    )
    monkeypatch.setattr(capture_runtime, "_is_windows", lambda: False)
    monkeypatch.setattr(
        character_state_module,
        "make_packet_handler",
        lambda engine: parser_packets.append,
    )
    monkeypatch.setattr("scapy.sendrecv.AsyncSniffer", FakeSniffer)
    return FakeSniffer, parser_packets


def test_offline_character_state_loads_one_profile_revision(monkeypatch):
    real_load = capture_module.load_opcode_profile
    calls = []

    def counted_load(path):
        calls.append(path)
        return real_load(path)

    monkeypatch.setattr(capture_module, "load_opcode_profile", counted_load)
    monkeypatch.setattr(character_state_module, "iter_pcap_file", lambda *args: ())

    profile = JULY17_OPCODE_PROFILE
    state = analyze_character_load_pcap(
        "unused.pcapng",
        opcode_profile=profile,
    )

    assert calls == [profile]
    assert state.provenance.profile_source == str(profile)


def test_offline_character_load_retains_a_large_out_of_order_storage_frame(
    monkeypatch,
):
    message = bytearray(257)
    message[:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x126D).to_bytes(2, "little")
    message[16:18] = (1).to_bytes(2, "little")
    message[27:31] = (0x20).to_bytes(4, "little")
    message[36:40] = (7003).to_bytes(4, "little")
    message[40:44] = (42).to_bytes(4, "little")
    message[71:79] = (1).to_bytes(8, "little")
    resets = []

    def replay_delayed_prefix(_path, engine):
        segment = {
            "source_ip": "10.0.0.1",
            "source_port": 8889,
            "destination_ip": "10.0.0.2",
            "destination_port": 50000,
        }
        engine.process_tcp_segment(
            **segment,
            sequence=999,
            payload=b"",
            timestamp=1.0,
            syn=True,
        )
        yield None
        for offset, value in enumerate(message[1:], start=1):
            engine.process_tcp_segment(
                **segment,
                sequence=1000 + offset,
                payload=bytes((value,)),
                timestamp=1.0 + offset / 10_000,
            )
            yield None
        engine.process_tcp_segment(
            **segment,
            sequence=1000,
            payload=bytes(message[:1]),
            timestamp=1.1,
        )
        yield None
        engine.finish()
        resets.append(engine.tcp_gap_resets)

    monkeypatch.setattr(
        character_state_module,
        "iter_pcap_file",
        replay_delayed_prefix,
    )

    state = analyze_character_load_pcap(
        "unused.pcapng",
        opcode_profile=JULY17_OPCODE_PROFILE,
    )

    assert resets == [0]
    assert state.decoder_health.storage_status == "compatible"
    assert state.decoder_health.storage_messages_observed == 1
    assert state.decoder_health.storage_messages_decoded == 1
    assert state.decoder_health.storage_records_decoded == 1


def test_live_character_load_pins_profile_revision_at_construction(
    monkeypatch,
    character_load_live_fakes,
):
    real_load = capture_module.load_opcode_profile
    calls = []

    def counted_load(path):
        calls.append(path)
        return real_load(path)

    monkeypatch.setattr(capture_module, "load_opcode_profile", counted_load)
    session = CharacterLoadSession(
        opcode_profile=JULY17_OPCODE_PROFILE,
        capture_options=PacketCaptureOptions(interface="test-interface")
    )
    assert len(calls) == 1

    def unexpected_reload(_path):
        raise AssertionError("an existing session must not reload its profile")

    monkeypatch.setattr(capture_module, "load_opcode_profile", unexpected_reload)
    session.start()
    assert session._engine is not None
    manager = session._engine._flow_manager
    assert manager._max_pending_segments == 2048
    assert manager._max_pending_bytes == 8 * 1024 * 1024
    state = session.stop()

    assert state.provenance.profile_source == str(JULY17_OPCODE_PROFILE)

    monkeypatch.setattr(capture_module, "load_opcode_profile", counted_load)
    CharacterLoadSession(
        opcode_profile=JULY17_OPCODE_PROFILE,
        capture_options=PacketCaptureOptions(interface="test-interface")
    )
    assert len(calls) == 2


@pytest.mark.parametrize("suffix", [".pcap", ".pcapng"])
def test_live_character_load_can_save_every_filtered_raw_packet(
    tmp_path,
    character_load_live_fakes,
    suffix,
):
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw
    from scapy.utils import PcapReader

    FakeSniffer, parser_packets = character_load_live_fakes
    output = tmp_path / "new" / "capture" / f"character-load{suffix}"
    packet = (
        IP(src="203.0.113.1", dst="198.51.100.2")
        / TCP(
            sport=8889,
            dport=50000,
        )
        / Raw(b"raw-packet-evidence")
    )

    session = CharacterLoadSession(
        opcode_profile=JULY17_OPCODE_PROFILE,
        capture_options=PacketCaptureOptions(interface="test-interface"),
        save_pcap=output,
    )
    session.start()
    FakeSniffer.instances[-1].emit(packet)
    state = session.stop()

    assert parser_packets == [packet]
    assert session.save_pcap_path == output
    assert state.provenance.capture_mode == "live_capture"
    assert state.provenance.capture_path == str(output)
    with PcapReader(str(output)) as reader:
        saved_packets = list(reader)
    assert len(saved_packets) == 1
    assert bytes(saved_packets[0]) == bytes(packet)


def test_live_character_load_refuses_to_overwrite_an_existing_capture(
    tmp_path,
    character_load_live_fakes,
):
    output = tmp_path / "existing.pcapng"
    original = b"keep this capture"
    output.write_bytes(original)
    session = CharacterLoadSession(
        opcode_profile=JULY17_OPCODE_PROFILE,
        capture_options=PacketCaptureOptions(interface="test-interface"),
        save_pcap=output,
    )

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        session.start()

    assert output.read_bytes() == original
    assert isinstance(session.error, FileExistsError)
    assert not session.running
    assert session._capture is None
    assert session._capture_writer is None
    assert session._engine is None
    assert session._accumulator is None
    with pytest.raises(RuntimeError, match="single-use"):
        session.start()


def test_live_character_load_saves_packet_before_parser_failure(
    monkeypatch,
    character_load_live_fakes,
):
    FakeSniffer, _ = character_load_live_fakes

    class FakeWriter:
        def __init__(self):
            self.packets = []
            self.closed = False

        def write(self, packet):
            self.packets.append(packet)

        def close(self):
            self.closed = True

    writer = FakeWriter()
    monkeypatch.setattr(
        character_state_module, "_open_packet_writer", lambda path: writer
    )

    def failing_handler(engine):
        def fail(packet):
            raise RuntimeError("snapshot parser failed")

        return fail

    monkeypatch.setattr(character_state_module, "make_packet_handler", failing_handler)
    session = CharacterLoadSession(
        opcode_profile=JULY17_OPCODE_PROFILE,
        capture_options=PacketCaptureOptions(interface="test-interface"),
        save_pcap="failure.pcapng",
    )
    session.start()
    packet = object()

    with pytest.raises(RuntimeError, match="snapshot parser failed"):
        FakeSniffer.instances[-1].emit(packet)
    with pytest.raises(RuntimeError, match="snapshot parser failed"):
        session.stop()

    assert writer.packets == [packet]
    assert writer.closed


def test_live_character_load_surfaces_accumulation_limit_without_partial_result(
    monkeypatch,
    character_load_live_fakes,
):
    FakeSniffer, _ = character_load_live_fakes
    emitted = 0

    def record_emitter(engine):
        def emit(packet):
            nonlocal emitted
            emitted += 1
            engine._on_event(
                _snapshot_record(
                    timestamp=float(emitted),
                    # The harness calls the collector callback directly and
                    # therefore supplies no generic frame-tap evidence. Model
                    # the real midstream recovery contract with two exactly
                    # adjacent, fully decoded inventory wrappers.
                    sequence=100 + (emitted - 1) * 254,
                    storage=False,
                    instance_byte=emitted,
                ),
                b"",
            )

        return emit

    monkeypatch.setattr(character_state_module, "make_packet_handler", record_emitter)
    session = CharacterLoadSession(
        opcode_profile=JULY17_OPCODE_PROFILE,
        capture_options=PacketCaptureOptions(interface="test-interface"),
        capture_limits=ItemStateCaptureLimits(
            max_relevant_frames=10,
            max_snapshot_records=1,
            max_relevant_bytes=1_000,
        ),
    )
    session.start()
    FakeSniffer.instances[-1].emit(object())

    with pytest.raises(ItemStateCaptureLimitError) as raised:
        FakeSniffer.instances[-1].emit(object())
    with pytest.raises(ItemStateCaptureLimitError) as stopped:
        session.stop()

    assert stopped.value is raised.value
    assert session.error is raised.value
    assert session._result is None
    assert session._capture is None
    assert session._engine is None


def test_live_character_load_closes_writer_when_sniffer_start_fails(
    monkeypatch,
    character_load_live_fakes,
):
    class FakeWriter:
        closed = False

        def close(self):
            self.closed = True

    class FailingSniffer:
        def __init__(self, **kwargs):
            self.running = False

        def start(self):
            raise OSError("adapter unavailable")

    writer = FakeWriter()
    monkeypatch.setattr(
        character_state_module, "_open_packet_writer", lambda path: writer
    )
    monkeypatch.setattr("scapy.sendrecv.AsyncSniffer", FailingSniffer)
    session = CharacterLoadSession(
        opcode_profile=JULY17_OPCODE_PROFILE,
        capture_options=PacketCaptureOptions(interface="test-interface"),
        save_pcap="startup.pcap",
    )

    with pytest.raises(OSError, match="adapter unavailable"):
        session.start()

    assert writer.closed
    assert isinstance(session.error, OSError)
    assert not session.running
    assert session.frames_seen == 0
    assert session._capture is None
    assert session._capture_writer is None
    assert session._engine is None
    assert session._accumulator is None
    with pytest.raises(RuntimeError, match="single-use"):
        session.start()
    with pytest.raises(RuntimeError, match="was not started"):
        session.stop()


def test_live_character_load_times_out_and_cleans_every_startup_resource(
    monkeypatch,
    character_load_live_fakes,
):
    class FakeWriter:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    class FakeSocket:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    class NeverReadySniffer:
        instances = []

        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.running = False
            self.exception = None
            self.stop_calls = 0
            self.__class__.instances.append(self)

        def start(self):
            # Model an alive backend that never invokes started_callback.
            self.running = True

        def stop(self):
            self.stop_calls += 1
            self.running = False

    writer = FakeWriter()
    capture_socket = FakeSocket()
    monkeypatch.setattr(
        character_state_module,
        "_open_packet_writer",
        lambda path: writer,
    )
    monkeypatch.setattr(capture_runtime, "_is_windows", lambda: True)
    monkeypatch.setattr(
        capture_runtime,
        "_open_enlarged_windows_socket",
        lambda **kwargs: capture_socket,
    )
    monkeypatch.setattr(
        capture_runtime,
        "_new_async_sniffer",
        NeverReadySniffer,
    )
    monkeypatch.setattr(
        character_state_module,
        "_CHARACTER_LOAD_STARTUP_TIMEOUT_SECONDS",
        0.01,
    )
    session = CharacterLoadSession(
        opcode_profile=JULY17_OPCODE_PROFILE,
        capture_options=PacketCaptureOptions(interface="test-interface"),
        save_pcap="timeout.pcapng",
    )

    with pytest.raises(
        RuntimeError,
        match="timed out while opening the live capture interface",
    ):
        session.start()

    sniffer = NeverReadySniffer.instances[-1]
    assert sniffer.stop_calls == 1
    assert capture_socket.closed
    assert writer.closed
    assert isinstance(session.error, RuntimeError)
    assert not session.running
    assert session.frames_seen == 0
    assert session._capture is None
    assert session._capture_writer is None
    assert session._engine is None
    assert session._accumulator is None
    with pytest.raises(RuntimeError, match="single-use"):
        session.start()


def test_live_character_load_retains_dependencies_until_capture_thread_stops(
    monkeypatch,
    character_load_live_fakes,
):
    class ControlledThread:
        ident = 1234

        def __init__(self):
            self.alive = True
            self.join_calls = []

        def is_alive(self):
            return self.alive

        def join(self, timeout=None):
            self.join_calls.append(timeout)

    failure = OSError("capture stop request failed")

    class UncooperativeSniffer:
        instances = []

        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.running = False
            self.exception = None
            self.thread = ControlledThread()
            self.stop_calls = 0
            self.__class__.instances.append(self)

        def start(self):
            self.running = True
            self.kwargs["started_callback"]()

        def stop(self, join=True):
            self.stop_calls += 1
            assert join is False
            raise failure

    class FakeWriter:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    writer = FakeWriter()
    monkeypatch.setattr(
        capture_runtime,
        "_new_async_sniffer",
        UncooperativeSniffer,
    )
    monkeypatch.setattr(
        character_state_module,
        "_open_packet_writer",
        lambda path: writer,
    )
    session = CharacterLoadSession(
        opcode_profile=JULY17_OPCODE_PROFILE,
        capture_options=PacketCaptureOptions(interface="test-interface"),
        save_pcap="retained-cleanup.pcapng",
    )
    session.start()
    capture = session._capture
    engine = session._engine
    accumulator = session._accumulator
    assert capture is not None
    assert engine is not None
    assert accumulator is not None

    with pytest.raises(RuntimeError, match="cleanup is incomplete") as first:
        session.stop()

    sniffer = UncooperativeSniffer.instances[-1]
    assert sniffer.thread.join_calls == [
        capture_runtime._CAPTURE_JOIN_TIMEOUT_SECONDS
    ]
    assert first.value.__cause__ is failure
    assert session._capture is capture
    assert session._engine is engine
    assert session._accumulator is accumulator
    assert session._capture_writer is writer
    assert not writer.closed
    assert session.cleanup_incomplete

    sniffer.thread.alive = False
    sniffer.running = False
    with pytest.raises(RuntimeError) as retried:
        session.stop()

    assert retried.value is first.value
    assert capture.stopped
    assert writer.closed
    assert session._capture is None
    assert session._engine is None
    assert session._capture_writer is None
    assert not session.cleanup_incomplete
    with pytest.raises(RuntimeError) as repeated:
        session.stop()
    assert repeated.value is first.value


def test_character_load_retains_startup_dependencies_when_cleanup_is_incomplete(
    monkeypatch,
    character_load_live_fakes,
):
    startup_failure = RuntimeError("capture startup timed out")

    class IncompleteStartupCapture:
        instances = []

        def __init__(self, **kwargs):
            self.running = True
            self.stopped = False
            self.cleanup_incomplete = True
            self.cleanup_error = RuntimeError("capture cleanup is incomplete")
            self.error = startup_failure
            self.__class__.instances.append(self)

        def start(self):
            raise startup_failure

        def stop(self):
            self.running = False
            self.stopped = True
            self.cleanup_incomplete = False
            self.cleanup_error = None

    class FakeWriter:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    writer = FakeWriter()
    monkeypatch.setattr(
        character_state_module,
        "LivePacketCapture",
        IncompleteStartupCapture,
    )
    monkeypatch.setattr(
        character_state_module,
        "_open_packet_writer",
        lambda path: writer,
    )
    session = CharacterLoadSession(
        opcode_profile=JULY17_OPCODE_PROFILE,
        capture_options=PacketCaptureOptions(interface="test-interface"),
        save_pcap="retained-startup.pcapng",
    )

    with pytest.raises(RuntimeError) as started:
        session.start()

    capture = IncompleteStartupCapture.instances[-1]
    assert started.value is startup_failure
    assert started.value.cleanup_owner is session
    assert session._capture is capture
    assert session._engine is not None
    assert session._accumulator is not None
    assert session._capture_writer is writer
    assert not writer.closed
    assert session.cleanup_incomplete

    with pytest.raises(RuntimeError) as stopped:
        session.stop()

    assert stopped.value is startup_failure
    assert capture.stopped
    assert writer.closed
    assert session._capture is None
    assert session._engine is None
    assert session._capture_writer is None
    assert not session.cleanup_incomplete
    with pytest.raises(RuntimeError) as repeated:
        session.stop()
    assert repeated.value is startup_failure


def test_live_character_load_successful_session_is_single_use_and_stop_is_cached(
    character_load_live_fakes,
):
    limits = ItemStateCaptureLimits(
        max_relevant_frames=7,
        max_snapshot_records=11,
        max_relevant_bytes=2_048,
    )
    session = CharacterLoadSession(
        opcode_profile=JULY17_OPCODE_PROFILE,
        capture_options=PacketCaptureOptions(interface="test-interface"),
        capture_limits=limits,
    )

    assert session.decoder_health.storage_status == "not_observed"
    session.start()
    assert session.decoder_health.storage_status == "not_observed"
    first = session.stop()
    second = session.stop()

    assert second is first
    assert session.decoder_health is first.decoder_health
    assert not session.running
    assert session.error is None
    assert session._capture is None
    assert session._capture_writer is None
    assert session._engine is None
    assert first.diagnostics is not None
    assert first.diagnostics.capture_limits.max_relevant_frames == 7
    assert first.diagnostics.capture_limits.max_snapshot_records == 11
    assert first.diagnostics.capture_limits.max_relevant_bytes == 2_048
    with pytest.raises(RuntimeError, match="single-use"):
        session.start()
